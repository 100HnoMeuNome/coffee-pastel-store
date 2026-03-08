# Coffee Pastel Store

A simple app to test and learning about security!

## Requirements

- Datadog account
- Active AI Guard
- LLM Observabilty
- Anthropic Key
- Docker

## How to run

- Clone this repo!
- Configure the .env file with your credentials
- Start the services with Docker Compose `docker compose up -d`

The application will run at http://localhost:5002/

![Login Page](/imagens/login.png)

Create a username and password (there are no security requirements).

![AI Barista](/imagens/cartao_credito.png)

You can place an order or go directly to the AI Barista. The app will always redirect you to the AI be creative and have fun.


Others features enabled in this app:
- IAST
- SCA Runtime
- Cloud Security
- App & Api Protection

## Events in Datadog

LLM Observability

![LLM Observability](/imagens/llm.png)

AI Guard

![AI Guard](/imagens/ai_guard.png)

## Documentation

For more information, see the official documentation:
- AI Guard https://docs.datadog.com/security/ai_guard/
- LLM Observability https://docs.datadoghq.com/llm_observability/
- Credit cards to test https://developer.pagbank.com.br/docs/cartoes-de-teste
