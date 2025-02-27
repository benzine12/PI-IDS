import json
import sqlite3

def main():
    connection = sqlite3.connect("wids.db")
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS macaddress (macPrefix TEXT, vendorName TEXT, private INTEGER,blockType TEXT ,lastUpdate TEXT)")

    with open('mac-vendors-export-2.json') as json_data:
        data = json.load(json_data)
        for i in data:
            cursor.execute(f"""INSERT INTO macaddress (macPrefix,vendorName, private, blockType,lastUpdate)
                        VALUES (?, ?, ?, ?, ?)""",
            (
                i.get('macPrefix',''),
                i.get('vendorName',''),
                int(i.get('private',0)),
                i.get('blockType',''),
                i.get('lastUpdate',''),
            )
)
    connection.commit()
    connection.close()
main()