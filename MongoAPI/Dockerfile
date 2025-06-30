# Use an official Python runtime as a base image.
# We choose a version based on Alpine Linux for a smaller image size.
FROM python:3.13-alpine

# Set the working directory in the container to /app
WORKDIR /app

# Install any necessary system dependencies for Python packages
# For example, if you use psycopg2 or other packages that require build tools,
# you might need to add them here. For a simple Flask/FastAPI app, these might not be strictly necessary,
# but it's good practice to include common ones if you encounter issues later.
# apk add --no-cache build-base

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any specified Python dependencies
# The --no-cache-dir option is used to prevent pip from storing cache,
# further reducing the image size.
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Python application file into the container at /app
# This should include MongoAPI.py and any other necessary Python files
COPY MongoAPI.py .

# Define the command to run your application.
# This assumes your MongoAPI.py file starts a web server.
# For Flask, it might be 'flask run --host=0.0.0.0 --port=5000' or using gunicorn.
# For a simple Python script, it's just 'python MongoAPI.py'.
# For demonstration, we'll use a simple Python command.
CMD ["python", "MongoAPI.py"]
