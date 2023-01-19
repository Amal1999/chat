import mysql.connector

class Database:
    def __init__(self):
        self.conn = mysql.connector.connect(
            host="127.0.0.1",
            user="root",
            database="ChatRoom"
        )
        
    def execute1(self, query, values=None):
        try: 
            cursor = self.conn.cursor()
            cursor.execute(query, values)
            self.conn.commit()
            cursor.close()
            return result
        except:
            return None

    def execute2(self, query, values=None):
        try: 
            cursor = self.conn.cursor()
            cursor.execute(query, values)
            result = cursor.fetchone()
            self.conn.commit()
            cursor.close()
            return result
        except:
            return None

    def close(self):
        self.conn.close()
