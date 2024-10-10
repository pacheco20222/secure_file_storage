import logging

class UserModel:
    def __init__(self, mysql):
        self.mysql = mysql
        self.logger = logging.getLogger(__name__)

    def create_user(self, username, email, hashed_password, otp_secret):
        try:
            cursor = self.mysql.connection.cursor()
            cursor.execute(
                'INSERT INTO users (username, email, password, otp_secret) VALUES (%s, %s, %s, %s)',
                (username, email, hashed_password.decode('utf-8'), otp_secret)
            )
            self.mysql.connection.commit()
            cursor.close()
            self.logger.info(f"User {email} created successfully.")
        except Exception as e:
            self.logger.error(f"Error creating user {email}: {e}")
            raise

    def get_user_by_email(self, email):
        try:
            cursor = self.mysql.connection.cursor()
            cursor.execute('SELECT * FROM users WHERE email = %s', [email])
            user = cursor.fetchone()
            cursor.close()
            self.logger.info(f"Fetched user by email: {email}")
            return user
        except Exception as e:
            self.logger.error(f"Error fetching user by email {email}: {e}")
            return None

    def get_user_by_username(self, username):
        try:
            cursor = self.mysql.connection.cursor()
            cursor.execute('SELECT * FROM users WHERE username = %s', [username])
            user = cursor.fetchone()
            cursor.close()
            self.logger.info(f"Fetched user by username: {username}")
            return user
        except Exception as e:
            self.logger.error(f"Error fetching user by username {username}: {e}")
            return None

    def get_user_otp_secret(self, user_id):
        try:
            cursor = self.mysql.connection.cursor()
            cursor.execute('SELECT otp_secret FROM users WHERE id = %s', [user_id])
            secret = cursor.fetchone()[0]
            cursor.close()
            self.logger.info(f"Fetched OTP secret for user ID: {user_id}")
            return secret
        except Exception as e:
            self.logger.error(f"Error fetching OTP secret for user ID {user_id}: {e}")
            return None