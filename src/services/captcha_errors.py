"""Safe captcha failures shared without importing a browser runtime."""


class BrowserCaptchaError(RuntimeError):
    """A stage and fixed error category safe to return to the caller."""

    def __init__(self, stage: str, reason: str):
        self.stage = stage
        self.reason = reason
        # Only the native runner may prove that its submit button was never
        # armed. A stage name alone does not establish upstream acceptance.
        self.submission_pending = None
        super().__init__(f"浏览器验证码失败 [{stage}/{reason}]")
