import ast
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
import sys
from types import SimpleNamespace


def test_attachments(script):
    # Exercise both legacy helper definitions without starting the log monitor.
    helpers = [
        node for node in ast.parse(script.read_text()).body
        if isinstance(node, ast.FunctionDef) and node.name == "send_email_with_attachment"
    ]
    assert len(helpers) == 2
    log = "fixture log\nSecond line\n"

    for helper in helpers:
        sent = []

        class SMTP:
            def __init__(self, *_args):
                pass

            def starttls(self):
                pass

            def login(self, *_args):
                pass

            def send_message(self, message):
                sent.append(message)

            def quit(self):
                pass

        scope = dict(
            smtplib=SimpleNamespace(SMTP=SMTP), encoders=encoders,
            MIMEBase=MIMEBase, MIMEMultipart=MIMEMultipart, MIMEText=MIMEText,
            SMTP_SERVER="localhost", SMTP_PORT=587, EMAIL_ADDRESS="from@example.test",
            EMAIL_PASSWORD="unused", log_action=lambda _message: None,
        )
        exec(compile(ast.Module(body=[helper], type_ignores=[]), str(script), "exec"), scope)
        scope[helper.name]("Fixture", "Details", "to@example.test", log)
        assert len(sent) == 1
        attachment = sent[0].get_payload()[1]
        assert attachment.get_filename() == "snitch.log"
        assert attachment.get_payload(decode=True) == log.encode("utf-8")


if __name__ == "__main__":
    test_attachments(Path(sys.argv[1]))
