# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app/play_integrity_pkg/
COPY . /app/play_integrity_pkg/

# Make port $PORT available to the world outside this container
# Cloud Run sets this environment variable.
EXPOSE $PORT

# Define environment variable
ENV PORT 8080

ENV PLAY_INTEGRITY_PACKAGE_NAME="dev.keiji.deviceintegrity"

# Run app.py when the container launches
CMD exec gunicorn -b :$PORT play_integrity_pkg.api:app
