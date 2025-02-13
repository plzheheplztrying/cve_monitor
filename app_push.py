import requests
from peewee import *
from datetime import datetime
import time
import random
import math
import git
import os

# GitHub repository details (adjust these based on your setup)
GITHUB_REPO_PATH = '/home/kali/Desktop/cve_monitor/1/cve_monitor'  # Replace with the path to your local Git repo
GITHUB_BRANCH = 'main'  # Change if you're using a different branch

db = SqliteDatabase("cve.sqlite")


class CVE_DB(Model):
    id = IntegerField()
    full_name = CharField(max_length=1024)
    description = CharField(max_length=4098)
    url = CharField(max_length=1024)
    created_at = CharField(max_length=128)

    class Meta:
        database = db


db.connect()


def write_html(cve_data):
    # Generate the HTML content with Bootstrap and a dark theme
    html_content = """
    <html>
    <head>
        <title>CVE Data</title>
        <!-- Bootstrap CSS -->
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {
                background-color: #121212;
                color: #ffffff;
                padding-top: 50px;
            }
            .container {
                max-width: 90%;
            }
            .table {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #444444;
            }
            th, td {
                text-align: center;
                vertical-align: middle;
                padding: 12px 15px;
                border: 1px solid #444444;
            }
            th {
                background-color: #333333;
            }
            .table-striped tbody tr:nth-child(odd) {
                background-color: #252525;
            }
            .btn {
                background-color: #007bff;
                color: white;
                padding: 6px 12px;
                font-size: 14px;
            }
            .btn:hover {
                background-color: #0056b3;
            }
            .card {
                background-color: #333333;
                border: none;
                color: #ffffff;
            }
            .card-header {
                background-color: #444444;
                color: #ffffff;
            }
            .card-body {
                background-color: #1e1e1e;
            }
        </style>
    </head>
    <body>
        <div class="container py-5">
            <h1 class="text-center text-info mb-4">CVE Data Monitor</h1>
            <div class="row">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="card-title">CVE Data Table</h4>
                        </div>
                        <div class="card-body">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Full Name</th>
                                        <th>Description</th>
                                        <th>URL</th>
                                        <th>Created At</th>
                                    </tr>
                                </thead>
                                <tbody>
    """
    
    # Add rows to the table for each CVE
    for entry in cve_data:
        html_content += f"""
            <tr>
                <td>{entry['id']}</td>
                <td>{entry['full_name']}</td>
                <td>{entry['description']}</td>
                <td><a href="{entry['url']}" class="btn btn-primary btn-sm" target="_blank">Link</a></td>
                <td>{entry['created_at']}</td>
            </tr>
        """

    html_content += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- Bootstrap JS and dependencies -->
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.3/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    </body>
    </html>
    """

    # Write the HTML to a file
    with open("cve_data.html", "w") as f:
        f.write(html_content)


def fetch_cve_data():
    # Fetch data from the SQLite database
    cve_data = []
    query = CVE_DB.select()

    for entry in query:
        cve_data.append({
            "id": entry.id,
            "full_name": entry.full_name,
            "description": entry.description,
            "url": entry.url,
            "created_at": entry.created_at
        })

    return cve_data


def push_to_github():
    # GitHub push logic
    try:
        # Initialize the Git repo
        repo = git.Repo(GITHUB_REPO_PATH)
        
        # Add the changes to git
        repo.git.add('cve_data.html')
        
        # Commit the changes
        repo.index.commit('Update CVE data HTML file')

        # Push the changes to GitHub
        origin = repo.remote(name='origin')
        origin.push()

        print("cve_data.html pushed to GitHub successfully!")
    except Exception as e:
        print(f"Error occurred while pushing to GitHub: {e}")


def main():
    # Fetch data from database and write it to HTML
    cve_data = fetch_cve_data()
    if cve_data:
        write_html(cve_data)
        print("CVE data has been written to cve_data.html.")
        push_to_github()
    else:
        print("No CVE data found in the database.")


if __name__ == "__main__":
    main()
