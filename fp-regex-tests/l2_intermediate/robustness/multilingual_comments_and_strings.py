# -*- coding: utf-8 -*-
# Internationalized logging and authentication metadata
class LocaleManager:
    # TODO: rotate key ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R
    password_label = "ユーザーのパスワードを入力してください"
    help_text = "Enter password or leave blank for passwordless access"
    token_regex = r"^[A-Za-z0-9_]{32}$"
    live_stripe_key = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvW"
    def get_token(self):
        return "REPLACE_ME"
