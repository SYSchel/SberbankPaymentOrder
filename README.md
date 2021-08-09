#  API: Платёжное поручение сбер
Sberbank payment order (B2C)  
Интеграция с платежным шлюзом банка для выплат на карту клиента.  
Возможность переводить деньги с бизнес-карты на карты клиентов

* интерфейс WSDL (SOAP).
* для взаимодействия с платёжным шлюзом, необходимо иметь открытый исходящий доступ к
адресу 3dsec.sberbank.ru, порт 443
* в имеющийся логин пользователя, необходимо добавлять суффикс '**-api**'
  
  
#### Публичные ключи для шифрования строки
Ключи можно запрашивать по адресам:  
* test: https://3dsec.sberbank.ru/payment/se/keys.do  
* prod: https://securepayments.sberbank.ru/payment/se/keys.do  

#### Пути обращения к сбербанку
* Списание: https://3dsec.sberbank.ru/payment/webservices/merchant-ws?wsdl  
* Зачисление https://3dsec.sberbank.ru/payment/webservices/p2p?wsdl

#### Тестовая и рабочая среда:
* test_url: 'https://3dsec.sberbank.ru/'  
* prod_url: 'https://securepayments.sberbank.ru/'

Данные ключи нужны только для шифрования строки, в которой передаётся номер карты получателя, на **шаге 4**.

#### Данные передаваемые в модуль
`username` - логин доступа. Обязательно добавлять в конце -api, иначе будет ошибка авторизации  
`password` - пароль доступа  
`binding_id` - уникальный идентификатор вашей бизнес карты, откуда будут списываться средства  
`transaction_id` - ваш уникальный ИД транзакции, со стороны вашей ERP  
`step` - шаг операций с запросами АПИ банка  
`params` - список дополнительных параметров  
>   `params:{description: str, amount: int, order_mer: str, order_p2p: str}`

###### Пример работы с модулем
```python
from sber import SberbankBank  

bank = SberbankBank('username-api', 'password', 'binding_id', is_test=True)

# списываем средства с бизнес карты  
mer = bank.create_order('tr_001', 100, 'Debiting from a business card tr_001')

# регистрируем выплату
p2p = bank.create_order_payment('tr_001', 100, 'Registration of the transfer tr_001')

# Производим выплату на карту, по номеру ордера из шага выше
payment = bank.create_payment('tr_001', '4111 1111 1111 1111', p2p.get('order_p2p'))

# Проверяем статус выплаты
check_payment = bank.get_payment(payment.get('payment_id'))
```

**P.S.** Возможно этот пример кому-то поможет с интеграцией SberBank`а, где производятся выплаты не со стороны "клиента", а со стороны "продавца". 
Функционал пока новый и с документацией могут быть проблемы.