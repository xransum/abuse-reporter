"""Database interface for managing reported IP addresses."""

import sqlite3


class ReportsDatabase:
    """Interface for managing reported IP addresses in a SQLite database."""

    def __init__(self, db_name: str):
        """Init the database connection and ensures the required table exists.

        Args:
            db_name (str): The name of the SQLite database file to connect to.

        This method establishes a connection to the SQLite database specified by
        `db_name` and creates a cursor for executing SQL commands. If the table
        `reported_ips` does not already exist, it is created with the following
        schema:
            - ip_addr (TEXT): The primary key representing the reported IP
                address.
            - date_added (TEXT): The date the IP address was added.

        Additionally, it retrieves and commits the table information to ensure
        the database schema is up-to-date.
        """
        self.con = sqlite3.connect(db_name)
        self.cur = self.con.cursor()

        self.cur.execute(
            """
            CREATE TABLE IF NOT EXISTS reported_ips (
                ip_addr TEXT PRIMARY KEY,
                date_added TEXT
            )
        """
        )

        # check existing columns
        self.cur.execute("PRAGMA table_info(reported_ips)")
        self.con.commit()

    def get_reported_ip_addrs(self) -> list:
        """Retrieves a list of reported IP addresses from the database.

        Returns:
            list: A list of reported IP addresses.
        """
        self.cur.execute("SELECT ip_addr FROM reported_ips")
        return [row[0] for row in self.cur.fetchall()]

    def get_reported_ip(self, ip_addr: str) -> dict | None:
        """Retrieves the details of a reported IP address.

        Args:
            ip_addr (str): The IP address to retrieve.

        Returns:
            dict | None: A dictionary containing the IP address and date added,
                         or None if the IP address is not found.
        """
        self.cur.execute(
            (
                "SELECT ip_addr, date_added FROM reported_ips WHERE ip_addr"
                "= ? LIMIT 1"
            ),
            (ip_addr,),
        )
        result = self.cur.fetchone()
        if result:
            return {"ip_addr": result[0], "date_added": result[1]}

        return None

    def is_ip_addr_reported(self, ip_addr: str) -> bool:
        """Checks if an IP address is already reported.

        Args:
            ip_addr (str): The IP address to check.

        Returns:
            bool: True if the IP address is reported, False otherwise.
        """
        reported_ip = self.get_reported_ip(ip_addr)
        if reported_ip:
            print(
                f"Already reported {reported_ip['ip_addr']} on "
                f"{reported_ip['date_added']}, skipping."
            )
            return True
        return False

    def add_reported_ip_addr(self, ip_addr: str, date_added: str | None = None):
        """Adds an IP address to the reported_ips table.

        Args:
            ip_addr (str): The IP address to add.
            date_added (str, optional): The date the IP was added. Defaults to
                the current date.
        """
        if date_added is None:
            # Use SQLite's date function for the default value
            date_added = "date('now')"
            self.cur.execute(
                f"""
                INSERT OR IGNORE INTO reported_ips (ip_addr, date_added)
                VALUES (?, {date_added})
                """,
                (ip_addr,),
            )

        else:
            self.cur.execute(
                """
                INSERT OR IGNORE INTO reported_ips (ip_addr, date_added)
                VALUES (?, ?)
                """,
                (ip_addr, date_added),
            )

        self.con.commit()

    def close(self):
        """Closes the database connection."""
        self.con.close()
