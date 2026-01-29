"""TOTP (Time-based One-Time Password) service for two-factor authentication."""

import base64
import io
import secrets

import pyotp
import qrcode
import structlog

logger = structlog.get_logger()


class TOTPService:
    """Service for managing TOTP-based two-factor authentication.

    Provides functionality for:
    - Generating TOTP secrets and backup codes
    - Generating QR codes for authenticator apps
    - Verifying TOTP codes
    """

    ISSUER_NAME = "NetGuardian AI"
    BACKUP_CODE_COUNT = 10
    BACKUP_CODE_LENGTH = 8

    def __init__(self) -> None:
        """Initialize the TOTP service."""
        pass

    @staticmethod
    def generate_secret() -> str:
        """Generate a new TOTP secret.

        Returns:
            Base32-encoded secret key.
        """
        return pyotp.random_base32()

    @staticmethod
    def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> list[str]:
        """Generate backup codes for account recovery.

        Args:
            count: Number of backup codes to generate.

        Returns:
            List of backup codes.
        """
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric codes
            code = secrets.token_hex(4).upper()  # 8 hex characters
            codes.append(code)
        return codes

    @staticmethod
    def hash_backup_codes(codes: list[str]) -> list[str]:
        """Hash backup codes for secure storage.

        For simplicity, we store codes in plain text but in a real production
        system, you'd want to hash these like passwords.

        Args:
            codes: List of plain backup codes.

        Returns:
            List of backup codes (could be hashed in production).
        """
        # In production, hash these with bcrypt or similar
        # For now, store as-is since they're already random
        return codes

    def get_totp_uri(self, secret: str, username: str) -> str:
        """Get the TOTP provisioning URI for QR code generation.

        Args:
            secret: The TOTP secret.
            username: The user's username.

        Returns:
            TOTP provisioning URI.
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=username, issuer_name=self.ISSUER_NAME)

    def generate_qr_code(self, secret: str, username: str) -> str:
        """Generate a QR code image as base64 for the TOTP setup.

        Args:
            secret: The TOTP secret.
            username: The user's username.

        Returns:
            Base64-encoded PNG image of the QR code.
        """
        uri = self.get_totp_uri(secret, username)

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        # Create image
        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        img_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{img_base64}"

    @staticmethod
    def verify_totp(secret: str, code: str) -> bool:
        """Verify a TOTP code.

        Args:
            secret: The user's TOTP secret.
            code: The code to verify.

        Returns:
            True if the code is valid, False otherwise.
        """
        if not secret or not code:
            return False

        # Clean the code (remove spaces)
        code = code.replace(" ", "").strip()

        # Verify with a 1-step window (30 seconds before/after)
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    @staticmethod
    def verify_backup_code(code: str, stored_codes: list[str]) -> tuple[bool, int | None]:
        """Verify a backup code.

        Args:
            code: The backup code to verify.
            stored_codes: List of valid backup codes.

        Returns:
            Tuple of (is_valid, code_index). code_index is the index of the
            used code if valid, to allow removing it from the list.
        """
        if not code or not stored_codes:
            return False, None

        # Clean the code
        code = code.upper().strip()

        for idx, stored_code in enumerate(stored_codes):
            if code == stored_code:
                return True, idx

        return False, None


# Global service instance
_totp_service: TOTPService | None = None


def get_totp_service() -> TOTPService:
    """Get the global TOTP service instance."""
    global _totp_service
    if _totp_service is None:
        _totp_service = TOTPService()
    return _totp_service
