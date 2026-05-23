# HW-05 WebSocket Protobuf Chat

Чат на чистом JavaScript и сервере Go. Обмен идет через WebSocket в binary mode, payload каждого WebSocket-фрейма кодируется через Protocol Buffers.

## Возможности

- сервер на Go поверх `net.Listener`, `net.Conn`, `bufio`;
- ручной WebSocket handshake и ручная обработка WebSocket-фреймов;
- бизнес-протокол `proto3` в `proto/chat.proto`;
- чистый HTML и JavaScript без фреймворков;
- несколько клиентов в разных вкладках браузера;
- имя пользователя и команда присоединения;
- защита от одинаковых имен;
- broadcast-сообщения и приватные сообщения формата `@name текст`;
- JPEG/PNG изображения до 1 МБ;
- иконка пользователя при подключении;
- история: до 50 сообщений и 50 изображений;
- при подключении отправляется история и последнее изображение.

## Запуск

```bash
cd HW-05
go run ./cmd/server
```

После запуска открыть:

```text
http://127.0.0.1:8080
```

Для проверки нескольких клиентов откройте эту страницу в двух или трех вкладках браузера.

## Приватное сообщение

В поле сообщения написать:

```text
@durov привет
```

Если пользователя `durov` нет в чате, сервер вернет protobuf-ответ с ошибкой, а клиент покажет ее на странице.

## Структура

```text
HW-05/
├── cmd/server/main.go
├── internal/
│   ├── app/          # application service
│   ├── config/       # параметры запуска
│   ├── domain/       # доменная модель и правила
│   ├── protocol/     # сгенерированный protobuf-код
│   ├── server/       # TCP/HTTP/WebSocket
│   └── websocket/    # WebSocket handshake и frames поверх net.Conn
├── proto/chat.proto
├── web/index.html
├── README.md
└── report.typ
```
