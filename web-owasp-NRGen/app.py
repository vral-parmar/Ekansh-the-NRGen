from fileinput import filename
import pandas
import os, secrets
from flask import Flask, current_app, render_template, request, redirect, url_for, flash

app = Flask(__name__)
secret_keys = secrets.token_hex(16)

app.config['SECRET_KEY'] = secret_keys
UPLOAD_FOLDER = 'static/files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['UPLOAD_EXTENSIONS'] = ['.csv']



@app.route('/')
def index():
    return render_template('index.html')

# Get the uploaded files


@app.route("/", methods=['POST'])
def uploadFiles():
    try:
        # get the uploaded file
        uploaded_file = request.files['file']
        uploaded_file.filename = 'one.csv'

        # Checking filename is not empty & extension is .csv & MIME type is text/csv
        if uploaded_file.filename != '' and uploaded_file.filename.split('.')[1] == 'csv' and uploaded_file.content_type == 'text/csv':
            file_path = os.path.join(
                app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            # set the file path
            uploaded_file.save(file_path)
            return redirect(url_for('expo'))
        else:
            flash('File is not supported', 'error')
            return redirect(url_for('index'))
    except Exception as e:
        flash("Upload Failure", "error")
        redirect(url_for("index"))


@app.route('/expo')
def expo():
    filename = os.path.join(app.config['UPLOAD_FOLDER'], 'one.csv')

        # to read the csv file using the pandas library
    data = pandas.read_csv(filename, header=0,encoding='cp1252')

        # Check whether CSV file is empty or not
    data_count = list(data)
    row_count = len(data)
    if row_count == 0:
        flash("CSV must contain 1 row",'error')
        return redirect(url_for('index'))
        # remove file from dir
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], 'one.csv'))

        # filter data
    data = data.filter(['OWASP 2021 Classification', 'Severity', 'Vulnerability', 'Description', 'Impact', 'URL',
                        'Remediation', 'References', 'CVSS v3', 'Vector', 'CWE'])

        # drop row which contain None severity
    #data = data.drop(data.index[data['Severity'] == 'None'])

        # Sorting of data on the basis of Risk Severity
    data = data.replace(to_replace='Low', value='ZZZ')
    data = data.sort_values('Severity')
    data = data.replace(to_replace='ZZZ', value='Low')
    data.head
    myData = data.values
    return render_template('home.html', myData=myData)

if __name__ == "__main__":
    app.run(host="localhost", port=int("5000"), debug=True)
