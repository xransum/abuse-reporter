import sqlite3


class ReportsDatabase:
    """
    ReportsDatabase is a class that provides an interface for managing a database
    of reported IP addresses. It allows adding, retrieving, and checking the existence
    of reported IPs in the database.
    Attributes:
        con (sqlite3.Connection): The SQLite database connection object.
        cur (sqlite3.Cursor): The SQLite database cursor object.
    Methods:
        __init__(db_name: str):
            Initializes the database connection and creates the `reported_ips` table
            if it does not already exist.
        get_reported_ip_addrs() -> list:
            Retrieves a list of all reported IP addresses from the database.
        get_reported_ip(ip_addr: str) -> dict | None:
            Retrieves the details of a specific reported IP address, including the
            date it was added. Returns None if the IP address is not found.
        is_ip_addr_reported(ip_addr: str) -> bool:
            Checks if a specific IP address has already been reported. Returns True
            if the IP address is found, otherwise False.
        add_reported_ip_addr(ip_addr: str, date_added: str = None):
            Adds a new IP address to the `reported_ips` table. If `date_added` is not
            provided, the current date is used as the default value.
    """

    def __init__(self, db_name: str):
        """
        Initializes the ReportsDatabase instance by connecting to the SQLite
            database.

        Args:
            db_name (str): The name of the SQLite database file.
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
        """
        Retrieves a list of reported IP addresses from the database.

        Returns:
            list: A list of reported IP addresses.
        """

        self.cur.execute("SELECT ip_addr FROM reported_ips")
        return [row[0] for row in self.cur.fetchall()]

    def get_reported_ip(self, ip_addr: str) -> dict | None:
        """
        Retrieves the details of a reported IP address.

        Args:
            ip_addr (str): The IP address to retrieve.

        Returns:
            dict | None: A dictionary containing the IP address and date added,
                         or None if the IP address is not found.
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
        """
        Checks if an IP address is already reported.

        Args:
            ip_addr (str): The IP address to check.

        Returns:
            bool: True if the IP address is reported, False otherwise.
        """
        reported_ip = self.get_reported_ip(ip_addr)
        if reported_ip:
            print(
                f"Already reported {reported_ip['ip_addr']} on {reported_ip['date_added']}, skipping."
            )
            return True
        return False

    def add_reported_ip_addr(self, ip_addr: str, date_added: str = None):
        """
        Adds an IP address to the reported_ips table.

        Args:
            ip_addr (str): The IP address to add.
            date_added (str, optional): The date the IP was added. Defaults to the current date.
        """
        if date_added is None:
            date_added = (
                "date('now')"  # Use SQLite's date function for the default value
            )
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
