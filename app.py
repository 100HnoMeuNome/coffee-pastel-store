"""
Coffee & Pastelaria — Flask application
Instrumented with Datadog APM (ddtrace 4.5.1) and LLM Observability.

NOTE: This app contains INTENTIONALLY POOR security controls for demo/educational purposes.
Do NOT use these patterns in production.
"""

import logging
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import anthropic

# LLM Observability — imported before app creation.
# ddtrace-run (used in CMD) handles APM auto-instrumentation for Flask/SQLite/etc.
from ddtrace.llmobs import LLMObs
from ddtrace.appsec.ai_guard import (
    new_ai_guard_client,
    AIGuardAbortError,
    AIGuardClientError,
    Message,
    Options,
)
import ddtrace.internal.logger as ddlogger

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] [%(filename)s:%(lineno)d] "
           "[dd.service=%(dd.service)s dd.env=%(dd.env)s dd.version=%(dd.version)s "
           "dd.trace_id=%(dd.trace_id)s dd.span_id=%(dd.span_id)s] - %(message)s",
)

LLMObs.enable(
    ml_app=os.getenv("DD_LLMOBS_ML_APP", "coffee-pastel-ai"),
    agentless_enabled=os.getenv("DD_LLMOBS_AGENTLESS_ENABLED", "false").lower() == "true",
)

app = Flask(__name__)
logger = ddlogger.get_logger(__name__)

# SECURITY ISSUE: Weak, hardcoded fallback secret key — session tokens are predictable
app.secret_key = os.getenv("SECRET_KEY", "secret123")

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "store.db")

MENU = {
    "coffees": [
        {"id": 1, "name": "Espresso",   "price": 5.50,  "description": "Dose encorpada e intensa, extração perfeita"},
        {"id": 2, "name": "Cappuccino", "price": 8.00,  "description": "Espresso com leite vaporizado e espuma cremosa"},
        {"id": 4, "name": "Cold Brew",  "price": 10.00, "description": "Extração lenta a frio, servido com gelo"},
    ],
    "pasteis": [
        {"id": 6,  "name": "Pastel de Queijo",      "price": 6.00,  "description": "Massa crocante recheada com queijo derretido",    "image": "https://guiadacozinha.com.br/wp-content/uploads/2016/01/pastel-de-frango-e-bacon.webp"},
        {"id": 7,  "name": "Pastel de Carne",       "price": 7.00,  "description": "Carne moída temperada com ervas frescas",          "image": "https://guiadacozinha.com.br/wp-content/uploads/2016/01/pastel-de-frango-e-bacon.webp"},
        {"id": 8,  "name": "Pastel de Frango",      "price": 7.00,  "description": "Frango desfiado com catupiry cremoso",              "image": "https://guiadacozinha.com.br/wp-content/uploads/2016/01/pastel-de-frango-e-bacon.webp"},
        {"id": 10, "name": "Pastel Doce de Banana", "price": 6.50,  "description": "Banana caramelizada com canela e açúcar",          "image": "https://guiadacozinha.com.br/wp-content/uploads/2016/01/pastel-de-frango-e-bacon.webp"},
    ],
    "sobremesas": [
        {"id": 13, "name": "Pé de Moleque",         "price": 5.00,  "description": "Clássico brasileiro de amendoim com rapadura, crocante e irresistível", "image": "https://receitatodahora.com.br/wp-content/uploads/2023/11/pe-moleque-1611.jpg"},
    ],
}

SYSTEM_PROMPT = (
    "You are Barista AI, a friendly virtual barista for Café & Pastelaria — "
    "a cozy Brazilian coffee and pastel shop. You help customers choose from the menu, "
    "take orders, and collect delivery/payment information. Be warm, enthusiastic about food, and keep answers concise.\n\n"
    "Menu:\n"
    "CAFÉS: Espresso (R$5,50), Cappuccino (R$8,00), Cold Brew (R$10,00), "
    "Jacu Bird (R$28,00 — café raro processado pelo pássaro Jacu), "
    "Café Frutado e Fermentado (R$18,00 — specialty natural anaeróbico)\n"
    "PASTÉIS: Queijo (R$6,00), Carne (R$7,00), Frango com Catupiry (R$7,00), Doce de Banana (R$6,50)\n"
    "SOBREMESAS: Pé de Moleque (R$5,00)\n\n"
    "When a customer sends their order, confirm the items and total, then ask:\n"
    "1. Delivery or pickup? (Se entrega: ask for address and name. Se retirada: ask for name only.)\n"
    "2. Payment method: PIX, cartão de crédito/débito, or dinheiro.\n"
    "Confirm all details warmly before closing the order."
)


def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email    TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", user=session.get("username"))


@app.route("/menu")
def menu():
    return render_template("menu.html", menu=MENU, user=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # SECURITY ISSUE: SQL injection — user input directly concatenated into query string.
        # An attacker can log in as any user with: username = admin'--
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        conn = get_db()
        try:
            user = conn.execute(query).fetchone()
        except Exception as e:
            # SECURITY ISSUE: Raw exception/stack trace exposed to the client.
            return render_template("login.html", error=f"Database error: {e}")
        finally:
            conn.close()

        if user:
            # SECURITY ISSUE: No session fixation regeneration.
            session["username"] = user["username"]
            session["user_id"]  = user["id"]
            return redirect(url_for("menu"))

        # SECURITY ISSUE: Username enumeration possible via response timing differences.
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = success = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email    = request.form.get("email", "").strip()

        # SECURITY ISSUES:
        #   - No input length, format, or strength validation
        #   - Password stored in plain text (no hashing)
        #   - No email verification
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                (username, password, email),
            )
            conn.commit()
            success = "Account created! You can now log in."
        except sqlite3.IntegrityError:
            error = "Username already taken."
        finally:
            conn.close()

    return render_template("register.html", error=error, success=success)


@app.route("/logout")
def logout():
    # SECURITY ISSUE: Logout via GET request — no CSRF protection.
    session.clear()
    return redirect(url_for("index"))


@app.route("/chat")
def chat():
    if not session.get("username"):
        return redirect(url_for("login"))
    return render_template("chat.html", user=session["username"])


@app.route("/api/chat", methods=["POST"])
def api_chat():
    if not session.get("username"):
        return jsonify({"error": "Unauthorized"}), 401

    data         = request.get_json(silent=True) or {}
    user_message = data.get("message", "").strip()
    if not user_message:
        return jsonify({"error": "Empty message"}), 400

    # -----------------------------------------------------------------------
    # Datadog AI Guard — evaluate prompt (input) before sending to Claude
    # -----------------------------------------------------------------------
    try:
        ai_guard = new_ai_guard_client()
    except ValueError as e:
        logger.error("AI Guard client init failed — check DD_API_KEY and DD_APP_KEY: %s", e)
        ai_guard = None

    conversation: list[Message] = [
        Message(role="system", content=SYSTEM_PROMPT),
        Message(role="user", content=user_message),
    ]
    if ai_guard:
        try:
            ai_guard.evaluate(conversation, options=Options(block=True))
        except AIGuardAbortError:
            return jsonify({"error": "Your message was blocked by our security policy."}), 403
        except AIGuardClientError as e:
            logger.warning("AI Guard input evaluation failed (status=%s): %s", getattr(e, 'status', '?'), e)
        except Exception as e:
            logger.warning("AI Guard input evaluation unexpected error: %s", e)

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    # -----------------------------------------------------------------------
    # Datadog LLM Observability — instrument the Claude API call
    # -----------------------------------------------------------------------
    with LLMObs.llm(
        model_name="claude-sonnet-4-6",
        model_provider="anthropic",
        name="barista_chat",
        session_id=str(session.get("user_id", "anonymous")),
    ) as span:
        LLMObs.annotate(
            span=span,
            input_data=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_message},
            ],
            tags={
                "user":    session.get("username"),
                "feature": "barista_chat",
            },
        )

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )

        assistant_reply = response.content[0].text

        # -------------------------------------------------------------------
        # Datadog AI Guard — evaluate model response (output)
        # -------------------------------------------------------------------
        if ai_guard:
            try:
                ai_guard.evaluate(
                    conversation + [Message(role="assistant", content=assistant_reply)],
                    options=Options(block=True),
                )
            except AIGuardAbortError:
                return jsonify({"error": "The model response was blocked by our security policy."}), 403
            except AIGuardClientError as e:
                logger.warning("AI Guard output evaluation failed (status=%s): %s", getattr(e, 'status', '?'), e)
            except Exception as e:
                logger.warning("AI Guard output evaluation unexpected error: %s", e)

        LLMObs.annotate(
            span=span,
            output_data=[{"role": "assistant", "content": assistant_reply}],
            metrics={
                "input_tokens":  response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
        )

    return jsonify({"reply": assistant_reply})


if __name__ == "__main__":
    init_db()
    # SECURITY ISSUE: debug=True in production exposes an interactive debugger
    # and full stack traces to anyone who triggers an error.
    app.run(host="0.0.0.0", port=5002, debug=True)
