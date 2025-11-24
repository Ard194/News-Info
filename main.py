import logging
import os
import requests
import feedparser
import json
from google import genai
from google.genai.types import GenerationConfig
from datetime import datetime, timedelta

# Configurazione del Logging (per vedere l'output nei log di GitHub Actions)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- CONFIGURAZIONE E CHIAVI (Recuperate dalle variabili d'ambiente di GitHub Actions) ---

TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

if GEMINI_API_KEY:
    try:
        # Inizializza il client Gemini
        ai_client = genai.Client(api_key=GEMINI_API_KEY)
        logging.info("Client Gemini inizializzato.")
    except Exception as e:
        logging.error(f"Errore di inizializzazione Gemini: {e}")
        ai_client = None
else:
    ai_client = None
    logging.error("GEMINI_API_KEY non trovata. Il filtraggio AI non sarà eseguito.")

# Fonti RSS da monitorare (queste sono solo ESEMPI e devono essere verificate)
SOURCES = {
    "Android Security": "https://feeds.feedburner.com/AndroidSecurityBlog",
    "Microsoft Security": "https://www.microsoft.com/security/blog/feed/",
    "Workspace ONE Blog": "https://blogs.vmware.com/euc/feed",
    "Intune Blog Updates": "https://techcommunity.microsoft.com/gxcuf89793/rss/board?board.id=MicrosoftIntune&board.key=MicrosoftIntune"
    # Nota: Le API NVD e i bollettini Apple spesso richiedono logiche di scraping o API dirette più complesse
}

# --- FUNZIONI DI SUPPORTO ---

def call_ai_filter(title: str, summary: str, source: str) -> dict | None:
    """Chiama l'LLM per filtrare, valutare l'ufficialità e riassumere."""
    if not ai_client:
        return None

    # Prompt ottimizzato per il modello Gemini Pro
    prompt = f"""
    Analizza il seguente articolo:
    Titolo: {title}
    Riassunto Iniziale: {summary}
    Fonte: {source}

    Il tuo compito è:
    1. Determinare se l'articolo è una **notizia ufficiale di sicurezza (CVE/Bollettino)** o un **aggiornamento rilevante** per Android, iOS, macOS, Windows, Workspace ONE (Omnissa), Intune o MobileIron.
    2. Se è rilevante: crea un riassunto conciso in italiano (max 50 parole).
    3. Se NON è rilevante, rispondi solo con un JSON vuoto: {{"relevant": false}}.

    Se è rilevante, rispondi **SOLO** con un oggetto JSON in questo formato (usa 'false'/'true' per i booleani e null se non trovi l'ID o la Gravità):
    {{"relevant": true, "title": "{title}", "summary_ai": "<il tuo riassunto conciso in italiano>", "cve_id": "<ID CVE se trovato, altrimenti null>", "severity": "<Gravità stimata (Critical, High, Medium) se CVE, altrimenti null>", "source": "{source}"}}

    Sii estremamente selettivo e considera solo le fonti ufficiali o articoli che citano CVE ufficiali o modifiche di policy rilevanti per MDM.
    """

    try:
        response = ai_client.models.generate_content(
            model='gemini-2.5-flash', # Modello rapido e potente per questo tipo di compito
            contents=prompt,
            config=GenerationConfig(
                response_mime_type="application/json",
                response_schema={
                    "type": "object",
                    "properties": {
                        "relevant": {"type": "boolean"},
                        "title": {"type": "string"},
                        "summary_ai": {"type": "string"},
                        "cve_id": {"type": "string", "nullable": True},
                        "severity": {"type": "string", "nullable": True},
                        "source": {"type": "string"}
                    }
                }
            )
        )
        ai_output = json.loads(response.text)
        return ai_output

    except Exception as e:
        logging.error(f"Errore durante la chiamata LLM Gemini: {e}")
        return None

def create_adaptive_card(report_data: list) -> dict:
    """Crea un payload Adaptive Card per Teams."""
    
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M')
    
    if not report_data:
        return {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "type": "AdaptiveCard",
                    "body": [
                        {"type": "TextBlock", "text": "🤖 Report Settimanale di Sicurezza AI 🤖", "size": "Large", "weight": "Bolder"},
                        {"type": "TextBlock", "text": f"Nessuna notizia ufficiale di sicurezza rilevante filtrata questa settimana ({current_time}).", "wrap": True}
                    ],
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "version": "1.2"
                }
            }]
        }

    card_body = [
        {"type": "TextBlock", "text": "🤖 Report Settimanale di Sicurezza AI 🤖", "size": "Large", "weight": "Bolder"},
        {"type": "TextBlock", "text": f"Report generato dall'AI in data: {current_time}", "wrap": True}
    ]
    
    for item in report_data:
        # Mappa la severità al colore dello stile di Adaptive Card
        style_map = {
            'Critical': 'Attention',
            'High': 'Warning',
            'Medium': 'Default',
            'Low': 'Default'
        }
        severity_style = style_map.get(item.get('severity', 'Default'), 'Default')

        fact_set_elements = []
        if item.get('cve_id'):
            fact_set_elements.append({"title": "CVE ID:", "value": item['cve_id']})
        if item.get('severity'):
            fact_set_elements.append({"title": "Gravità Stimata:", "value": item['severity']})
            
        card_body.append({
            "type": "Container",
            "style": severity_style,
            "bleed": True,
            "items": [
                {"type": "TextBlock", "text": f"**🚨 {item['title']}**", "wrap": True, "size": "Medium"},
                {"type": "TextBlock", "text": f"*{item['summary_ai']}*", "wrap": True, "spacing": "Small"},
                {"type": "FactSet", "facts": fact_set_elements},
                {"type": "ActionSet", "actions": [
                    {"type": "Action.OpenUrl", "title": "Leggi Fonte Originale", "url": item['source']}
                ]}
            ]
        })

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "type": "AdaptiveCard",
                "body": card_body,
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.2"
            }
        }]
    }

def send_teams_report(payload: dict):
    """Invia il payload JSON a Teams."""
    if not TEAMS_WEBHOOK_URL:
        logging.error("URL del Webhook di Teams non trovato.")
        return False

    try:
        response = requests.post(
            TEAMS_WEBHOOK_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"}
        )
        if response.status_code == 200:
            logging.info("Report inviato a Teams con successo.")
            return True
        else:
            logging.error(f"Errore Teams: Status {response.status_code}, Response: {response.text}")
            return False
    except Exception as e:
        logging.error(f"Errore invio Teams: {e}")
        return False

# --- FUNZIONE PRINCIPALE ---

def main() -> None:
    """Funzione principale eseguita da GitHub Actions."""
    logging.info('Inizio esecuzione script di report settimanale.')

    # Filtra solo gli articoli degli ultimi 7 giorni
    last_week = datetime.now() - timedelta(days=7)
    filtered_reports = []

    # 1. LOOP DI RACCOLTA DATI
    for source_name, url in SOURCES.items():
        logging.info(f"Elaborazione fonte: {source_name}")
        try:
            feed = feedparser.parse(url)
            
            for entry in feed.entries:
                # Tentativo di filtrare gli articoli recenti basato sulla data di pubblicazione
                if hasattr(entry, 'published_parsed'):
                    pub_date = datetime(*entry.published_parsed[:6])
                    if pub_date < last_week:
                        continue # Salta se l'articolo è troppo vecchio

                title = entry.title
                summary = entry.summary if hasattr(entry, 'summary') else entry.description
                link = entry.link

                # 2. FILTRAGGIO AI
                ai_result = call_ai_filter(title, summary, link)
                
                if ai_result and ai_result.get("relevant"):
                    logging.info(f"Notizia rilevante trovata: {title}")
                    filtered_reports.append(ai_result)
                
        except Exception as e:
            logging.error(f"Errore nella raccolta dati da {source_name}: {e}")
            continue

    # 3. INVIO REPORT
    
    # Rimuovi i duplicati basati sul titolo per pulizia
    unique_reports = {item['title']: item for item in filtered_reports}.values()
    
    report_payload = create_adaptive_card(list(unique_reports))
    send_teams_report(report_payload)
    
    logging.info('Script di report terminato.')


# Assicurati che la funzione main venga chiamata quando lo script viene eseguito da GitHub Actions
if __name__ == "__main__":
    main()
