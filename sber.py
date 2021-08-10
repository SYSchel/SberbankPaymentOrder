"""
    
    Списание: https://3dsec.sberbank.ru/payment/webservices/merchant-ws?wsdl
    Зачисление https://3dsec.sberbank.ru/payment/webservices/p2p?wsdl

    Этапы работы(шаги):
        0 - списание[registerOrder]: Регистрация перевода в платежном шлюзе
        1 - списание[paymentOrderBinding]: Списание с бизнес-карты
        2 - списание[getOrderStatusExtended]: Подтверждение списания с бизнес-карты

       -1 - [reverseOrder] Отмена списания с бизнес-карты

        3 - зачисление[registerP2P]: Регистрация перевода в платежном шлюзе
        4 - зачисление[performP2P]: Перевод на карту с передачей номера карты
        5 - зачисление[getP2PStatus]: Проверка статуса операции зачисления

            На шаге 3 возвращается ссылка, при переходе по которой, можно ввести номер карты получателя
            и этим финализировать операцию. Если вы желаете передавать номер карты получателя самостоятельно,
            без перехода на страницу банка, тогда после шага 3, нужно отправить запрос шагом 4
"""

import requests
import re

from datetime import datetime
from pytz import timezone

from xml.etree import ElementTree
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from base64 import b64encode


class SberbankBank:
    """
    binding_id: Номер бизнес-карты, с которой будет происходить списание
    transaction_id: уникальный ИД заказа/транзакции, со стороны ERP
    step: шаг операций с запросами АПИ банка
    """

    test_url = 'https://3dsec.sberbank.ru/'
    prod_url = 'https://securepayments.sberbank.ru/'
    test_returnUrl = 'https://test.mysite.ru/callback/'
    prod_returnUrl = 'https://mysite.ru/callback/'
    public_key = './privatekey.pem'

    scenario = 22
    sts_mer = 600
    sts_p2p = 120
    step_range = [-1, 0, 1, 2, 3, 4, 5]  # Шаги для работы с API

    def __init__(self, username, password, binding_id, is_test=True):
        assert username, 'username must be defined'
        assert password, 'password must be defined'
        assert binding_id, 'bindingId must be defined'

        self.username = username
        self.password = password
        self.bindingId = binding_id
        self.is_test = is_test

    @property
    def url(self):
        return self.test_url if self.is_test else self.prod_url

    @property
    def return_url(self):
        return self.test_returnUrl if self.is_test else self.prod_returnUrl

    @property
    def pub_key(self):
        """
        Не обязательно, но сбер отдаёт ключ одной строкой, который не принемается библиотекой и
         требуется добавить после заголовка перенос строки.
        Публичные ключи, можно получить у сбера по адресам:
        test: https://3dsec.sberbank.ru/payment/se/keys.do
        prod: https://securepayments.sberbank.ru/payment/se/keys.do
        """
        type_begin = '-----BEGIN PUBLIC KEY-----'
        regex_begin = re.compile(r'^{type_begin}(\n|\r|\r\n).*'.format(type_begin=type_begin))
        return_key = ''
        if re.match(regex_begin, self.public_key):
            return_key = self.public_key
        else:
            return_key = self.public_key.replace(type_begin, type_begin + '\n')

        type_end = '-----END PUBLIC KEY-----'
        regex_end = re.compile(r'(\n|\r|\r\n){type_end}$'.format(type_end=type_end))
        if not re.match(regex_end, self.public_key):
            return_key = return_key.replace(type_end, '\n' + type_end)
        return return_key

    @staticmethod
    def _process_amount(value):
        """
        Преобразуем сумму в копейки, с учётом "банковского округления"
        """
        return round(value * 100)

    @property
    def _iso_datatime(self):
        """
        Получаем дату в ISO формате, для шага 4
        """
        return datetime.now().astimezone(timezone('Europe/Moscow')).isoformat(timespec='seconds')

    def _soap_auth(self, transaction_id, step):
        """
         Авторизация на сервере
        """

        must_und = "" if step < 3 else "env:mustUnderstand='1' soapenv:mustUnderstand='1'"
        return "<soapenv:Header>" \
               "<wsse:Security {must_und}" \
               " xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'" \
               " xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>" \
               "<wsse:UsernameToken wsu:Id='UsernameToken-{transaction_id}'>" \
               "<wsse:Username>{username}</wsse:Username>" \
               "<wsse:Password Type='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText'>{password}</wsse:Password>" \
               "</wsse:UsernameToken>" \
               "</wsse:Security>" \
               "</soapenv:Header>".format(
                                            must_und=must_und,
                                            transaction_id=transaction_id,
                                            username=self.username,
                                            password=self.password
                                        )

    def _soap_body(self, transaction_id, step, **params):
        """
        Тело запроса
            params: list
                description: str,
                amount: int,
                order_mer: str,
                order_p2p: str
        """

        # Разрешённые шаги
        if step not in self.step_range:
            message = 'Переданный шаг "{step}", отсутствует в списке допустимых {step_range}'.format(
                step=step, step_range=self.step_range)
            raise Exception(message)

        _xmlBody = ''

        # Регистрация перевода в платежном шлюзе
        if step == 0:
            print('-= method: mer:registerOrder')
            _ssl = "<features><feature>FORCE_SSL</feature></features>"
            _tds = "<features><feature>FORCE_TDS</feature></features>"

            _xmlBody = "<mer:registerOrder>" \
                       "<order merchantOrderNumber='{transaction_id}#'" \
                       " description='{description}'" \
                       " amount='{_process_amount}'" \
                       " currency='643'" \
                       " language='ru'" \
                       " sessionTimeoutSecs='{sts_mer}'" \
                       " bindingId='{bindingId}'>" \
                       "<returnUrl>{return_url}</returnUrl>" \
                       "<params name='mark' value='{transaction_id}' resident='1'/>" \
                       "{ssl}" \
                       "</order>" \
                       "</mer:registerOrder>".format(
                            transaction_id=transaction_id,
                            description=params.get('description'),
                            _process_amount=self._process_amount(params.get('amount')),
                            sts_mer=self.sts_mer,
                            bindingId=self.bindingId,
                            return_url=self.return_url,
                            ssl=_ssl if self.scenario > 20 else _tds
                        )

        # Списание с бизнес-карты
        if step == 1:
            print('-= method: mer:paymentOrderBinding')
            _xmlBody = "<mer:paymentOrderBinding>" \
                       "<order mdOrder='{order_mer}' bindingId='{bindingId}'></order>" \
                       "</mer:paymentOrderBinding>".format(order_mer=params.get('order_mer'), bindingId=self.bindingId)

        # Подтверждение списания с бизнес-карты
        if step == 2:
            print('-= method: mer:getOrderStatusExtended')
            _xmlBody = "<mer:getOrderStatusExtended>" \
                       "<order language='ru' orderId='{order_mer}'>" \
                       "<merchantOrderNumber>'{transaction_id}'</merchantOrderNumber>" \
                       "</order>" \
                       "</mer:getOrderStatusExtended>".format(order_mer=params.get('order_mer'),
                                                              transaction_id=transaction_id)

        # Отмена списания с бизнес-карты
        if step == -1:
            print('-= method: mer:reverseOrder')
            _xmlBody = "<mer:reverseOrder>" \
                       "<order language='ru' orderId='{order_mer}'>" \
                       "<params name='mark' value='{transaction_id}'/>" \
                       "</order>" \
                       "</mer:reverseOrder>".format(order_mer=params.get('order_mer'), transaction_id=transaction_id)

        # Регистрация перевода в платежном шлюзе
        if step == 3:
            print('-= method: p2p:registerP2P')
            _xmlBody = "<p2p:registerP2P>" \
                       "<arg0 language='ru'>" \
                       "<amount>{_process_amount}</amount>" \
                       "<currency>643</currency>" \
                       "<transactionTypeIndicator>A</transactionTypeIndicator>" \
                       "<orderNumber>{transaction_id}</orderNumber>" \
                       "<orderDescription>{description}</orderDescription>" \
                       "<returnUrl>{return_url}</returnUrl>" \
                       "<sessionTimeoutSecs>{sts_p2p}</sessionTimeoutSecs>" \
                       "<params name='mark' value='{transaction_id}' resident='1'/>" \
                       "<bindingId>{bindingId}</bindingId>" \
                       "<features><feature>WITHOUT_FROM_CARD</feature></features>" \
                       "</arg0>" \
                       "</p2p:registerP2P>".format(
                            _process_amount=self._process_amount(params.get('amount')),
                            transaction_id=transaction_id,
                            description=params.get('description'),
                            return_url=self.return_url,
                            sts_p2p=self.sts_p2p,
                            bindingId=self.bindingId
                        )

        # Перевод на карту с передачей номера карты
        if step == 4:
            #  Используем публичный ключ сбербанка, для шифрования строки с номером карты
            pub_key = RSA.importKey(self.pub_key)
            cipher = Cipher_PKCS1_v1_5.new(pub_key)

            card_pan = re.sub('[^0-9]', '', params.get('card_pan'))

            _str_to_crypt = "{data_iso}/{transaction_id}/{pan}///{order_p2p}".format(
                                data_iso=self._iso_datatime,
                                transaction_id=transaction_id,
                                pan=card_pan,
                                order_p2p=params.get('order_p2p')
                            )
            #  Шифруем получившуюся строку по требованию банка
            cipher_text = cipher.encrypt(_str_to_crypt.encode())
            b64msg = b64encode(cipher_text)

            cr_rsa = b64msg.decode('utf-8')
            _xmlBody = "<p2p:performP2P>" \
                       "<arg0 language='ru' type='WITHOUT_FROM_CARD'>" \
                       "<orderId>{order_p2p}</orderId>" \
                       "<toCard><seToken>{cr_rsa}</seToken></toCard>" \
                       "</arg0>" \
                       "</p2p:performP2P>".format(order_p2p=params.get('order_p2p'), cr_rsa=cr_rsa)

        # Проверка статуса операции зачисления
        if step == 5:
            _xmlBody = "<p2p:getP2PStatus>" \
                       "<arg0 language='ru'><orderId>{order_p2p}</orderId></arg0>" \
                       "</p2p:getP2PStatus>".format(order_p2p=params.get('order_p2p'))

        return "<soapenv:Body>{_xmlBody}</soapenv:Body>".format(_xmlBody=_xmlBody)

    def _soap_request(self, transaction_id, step, params):
        """
        Собираем SOAP сообщение и адрес запроса
        """
        _xmlBody = self._soap_body(transaction_id, step, **params)
        _engine = "http://engine.paymentgate.ru/webservices/"
        _mer = "mer='{_engine}merchant'".format(_engine=_engine)
        _p2p = "p2p='{_engine}p2p' xmlns:env='env'".format(_engine=_engine)
        _url = "{url}payment/webservices/{pth}?wsdl".format(url=self.url, pth='merchant-ws' if step < 3 else 'p2p')
        _xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
               "<soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/' xmlns:{pth}>".format(
                    pth=_mer if step < 3 else _p2p)
        xml_request = "{_xml}{_soap_auth}{_xmlBody}</soapenv:Envelope>".format(
                    _xml=_xml, _soap_auth=self._soap_auth(transaction_id, step), _xmlBody=_xmlBody)
        return self._request('POST', _url, data=xml_request)

    @staticmethod
    def _request(self, method, url, **kwargs):
        """
        :return:  xml object
        """
        headers = {
            'Accept-Encoding': 'gzip,deflate',
            'Content-type': 'text/xml;charset=utf-8'
        }

        response = requests.request(method, url, headers=headers, verify=True, **kwargs)
        result = response.text
        dom = ElementTree.fromstring(result)
        tree = dom.findall('*//return')
        if not tree:
            raise Exception('Ответ банка оказался неожиданным')
        if int(tree[0].attrib.get('errorCode')) > 0:
            raise Exception(
                '{errorMessage} (errorCode={errorCode})'.format(errorCode=tree[0].attrib.get('errorCode'),
                                                                errorMessage=tree[0].attrib.get('errorMessage')))
        return tree[0]

    """@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
          Примеры вызова методов к банку
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    """

    def create_order(self, transaction_id, amount, description):
        # Регистрируем списание средст с бизнес-карты: params(description, amount)
        register_order = self._soap_request(transaction_id, 0, {'amount': amount, 'description': description})
        order_mer = register_order.attrib.get('orderId')
        form_url = register_order.find('formUrl').text

        # Списываем с бизнес-карты  params(order_mer)
        binding_order = self._soap_request(transaction_id, 1, {'order_mer': order_mer})

        info = binding_order.attrib.get('info')
        redirect = binding_order.attrib.get('redirect')

        # Проверяем статус списания средств params(order_mer)
        get_status_order = self._soap_request(transaction_id, 2, {'order_mer': order_mer})

        # Если код списания средств пришёл НЕ 2, отменяем списание
        if int(get_status_order.attrib.get('orderStatus')) != 2:
            self._soap_request(transaction_id, -1, {'order_mer': order_mer})

            message = 'Не удалось списать с бизнес-карты необходимую сумму, производится отмена списания:' \
                      ' "orderStatus: {orderStatus}, errorMessage: {errorMessage}, decode: {decode}"'.format(
                            orderStatus=get_status_order.attrib.get('orderStatus'),
                            errorMessage=get_status_order.attrib.get('errorMessage'),
                            decode=get_status_order.attrib.get('orderStatus')
                        )
            raise Exception(message)
        return {'order_mer': order_mer, 'form_url': form_url, 'info': info, 'redirect': redirect, 'status': 2}

    def create_order_payment(self, transaction_id, amount, description):
        # Регистрация перевода в платёжном шлюзе
        register_p2p = self._soap_request(transaction_id, 3, {'amount': amount, 'description': description})

        order_p2p = register_p2p.find('orderId').text
        form_url = register_p2p.find('formUrl').text
        return {'order_p2p': order_p2p, 'form_url': form_url, 'status': 2}

    def create_payment(self, transaction_id, card_pan, order_p2p):
        # отправляем запрос на выплату, с передачей карты получателя
        perform_p2p = self._soap_request(transaction_id, 4, {'card_pan': card_pan, 'order_p2p': order_p2p})
        info = perform_p2p.find('info').text
        redirect = perform_p2p.find('redirect').text
        return {'info': info, 'redirect': redirect, 'status': 0, 'detail': 'Выплата подтверждена', 'id': order_p2p,
                'payment_id': order_p2p}

    def get_payment(self, order_p2p):
        # Получение статуса перевода и данных об карте

        p2p_status = self._soap_request(None, 5, {'order_p2p': order_p2p})
        orderNumber = p2p_status.find('orderNumber').text
        orderStatus = p2p_status.find('orderStatus').text
        panMaskedTo = p2p_status.find('panMaskedTo').text
        amount = p2p_status.find('amount').text
        fee = p2p_status.find('fee').text
        currency = p2p_status.find('currency').text
        orderDescription = p2p_status.find('orderDescription').text
        resultCode = p2p_status.find('resultCode').text

        return {
            'id': order_p2p,
            'detail': orderStatus,
            'status': orderStatus,
        }
