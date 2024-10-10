import logging

class FileModel:
    def __init__(self, mysql):
        self.mysql = mysql
        self.logger = logging.getLogger(__name__)

    def upload_file(self, filename, file_path, user_id):
        try:
            cursor = self.mysql.connection.cursor()
            cursor.execute(
                'INSERT INTO files (filename, filepath, user_id) VALUES (%s, %s, %s)',
                (filename, file_path, user_id)
            )
            self.mysql.connection.commit()
            cursor.close()
            self.logger.info(f"File {filename} uploaded successfully for user ID {user_id}.")
        except Exception as e:
            self.logger.error(f"Error uploading file {filename} for user ID {user_id}: {e}")
            raise

    def get_files_by_user(self, user_id):
        try:
            cursor = self.mysql.connection.cursor()
            cursor.execute('SELECT * FROM files WHERE user_id = %s', [user_id])
            files = cursor.fetchall()
            cursor.close()
            self.logger.info(f"Fetched files for user ID {user_id}.")
            return files
        except Exception as e:
            self.logger.error(f"Error fetching files for user ID {user_id}: {e}")
            return None
