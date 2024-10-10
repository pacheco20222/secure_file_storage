-- Create the database if it doesn't exist
CREATE DATABASE IF NOT EXISTS secure_storage;

-- Use the newly created database
USE secure_storage;

-- Create 'users' table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    otp_secret VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (email)  -- Adding an index on the email for quicker lookups
);

-- Create 'files' table for storing file metadata
CREATE TABLE IF NOT EXISTS files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    filepath VARCHAR(255) NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) 
    ON DELETE CASCADE ON UPDATE CASCADE  -- Cascades to manage file data when user data is deleted or updated
);
