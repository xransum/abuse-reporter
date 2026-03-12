"""Database interface for managing reported IP addresses."""

import sqlite3


class ReportsDatabase:
    """Interface for managing reported IP addresses in a SQLite database."""

    def __init__(self, db_path: str) -> None:
        """Initialise the database connection and ensure the required table exists.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.con = sqlite3.connect(db_path)
        self.cur = self.con.cursor()
        self.cur.execute(
            """
            CREATE TABLE IF NOT EXISTS reported_ips (
                ip_addr   TEXT PRIMARY KEY,
                date_added TEXT
            )
            """
        )
        self.cur.execute("PRAGMA table_info(reported_ips)")
        self.con.commit()

    def get_reported_ip_addrs(self) -> list[str]:
        """Return a list of all reported IP addresses.

        Returns:
            A list of IP address strings.
        """
        self.cur.execute("SELECT ip_addr FROM reported_ips")
        return [row[0] for row in self.cur.fetchall()]

    def get_reported_ip(self, ip_addr: str) -> dict[str, str] | None:
        """Return the record for a reported IP address, or None if not found.

        Args:
            ip_addr: The IP address to look up.

        Returns:
            A dict with ``ip_addr`` and ``date_added`` keys, or None.
        """
        self.cur.execute(
            "SELECT ip_addr, date_added FROM reported_ips WHERE ip_addr = ? LIMIT 1",
            (ip_addr,),
        )
        result = self.cur.fetchone()
        if result:
            return {"ip_addr": result[0], "date_added": result[1]}
        return None

    def is_ip_addr_reported(self, ip_addr: str) -> bool:
        """Return True if the IP address has already been reported.

        Args:
            ip_addr: The IP address to check.

        Returns:
            True if already reported, False otherwise.
        """
        return self.get_reported_ip(ip_addr) is not None

    def add_reported_ip_addr(self, ip_addr: str, date_added: str | None = None) -> None:
        """Insert an IP address into the reported_ips table.

        Args:
            ip_addr: The IP address to record.
            date_added: Optional ISO date string.  Defaults to SQLite's
                ``date('now')`` when not provided.
        """
        if date_added is None:
            self.cur.execute(
                "INSERT OR IGNORE INTO reported_ips (ip_addr, date_added)"
                " VALUES (?, date('now'))",
                (ip_addr,),
            )
        else:
            self.cur.execute(
                "INSERT OR IGNORE INTO reported_ips (ip_addr, date_added)"
                " VALUES (?, ?)",
                (ip_addr, date_added),
            )
        self.con.commit()

    def close(self) -> None:
        """Close the database connection."""
        self.con.close()
