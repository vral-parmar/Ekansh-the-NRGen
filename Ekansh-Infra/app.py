from flask import Flask, render_template, url_for, redirect, flash, request, send_file, send_from_directory, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import pandas, os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = 'supersecretkey'
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"
UPLOAD_FOLDER = 'static/files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['UPLOAD_EXTENSIONS'] = ['.csv']
myData = None

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
#this register
class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Register")
    def validate_username(self, username):
        existing_username = User.query.filter_by(username=username.data).first()
        if existing_username:
            raise ValidationError("Username already exist please choose another one")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("Login")

@app.route('/')
def home():
    if current_user.is_authenticated:
        return render_template('dashbord.html')
    else:
        return render_template('home.html')

@app.route('/dashbord', methods=['GET','POST'])
@login_required
def dashbord():
    return render_template('dashbord.html')

@app.route('/dash', methods=['POST'])
@login_required
def uploadFiles():
    try:
        # remove old file 
        filename = os.path.join(app.config['UPLOAD_FOLDER'], 'one.csv')
        if os.path.exists(filename):
            # Delete the file
            os.remove(filename)

        uploaded_file = request.files['file']
        # save new dataset
        uploaded_file.filename = 'one.csv'

        # Checking filename is not empty & extension is .csv & MIME type is text/csv
        if uploaded_file.filename != '' and uploaded_file.filename.split('.')[1] == 'csv' and uploaded_file.content_type == 'text/csv':
            file_path = os.path.join(
                app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            # set the file path
            uploaded_file.save(file_path)
            return redirect(url_for('report'))
        else:
            flash('File is not supported', 'error')
            return redirect(url_for('dashbord'))
    except Exception as e:
        flash("Upload Failure", "error")
        return redirect(url_for("dashbord"))

@app.route('/report')
@login_required
def report():
    try:
        filename = os.path.join(app.config['UPLOAD_FOLDER'], 'one.csv')

        # to read the csv file using the pandas library
        data = pandas.read_csv(filename, header=0)

        # Check whether CSV file is empty or not
        data_count = list(data)
        row_count = len(data)
        if row_count == 0:
            flash("CSV must contain 1 row",'error')
            return redirect(url_for('dashbord'))
        # remove file from dir
        #os.remove(os.path.join(app.config['UPLOAD_FOLDER'], 'one.csv'))

        # filter data
        data = data.filter(['CVE', 'CVSS v2.0 Base Score', 'CVSS v3.0 Base Score', 'Risk', 'Host', 'Protocol',
                        'Port', 'Name', 'Synopsis', 'Description', 'Solution', 'See Also', 'MSKB', 'Metasploit','Plugin Output'])


        # drop row which contain None severity
        data = data.drop(data.index[data['Risk'] == 'None'])

        # Remove duplicate data from by col Name
        data['Name'] = data['Name'].astype(str)
        data['CVE'] = data['CVE'].astype(str)

        unique_df = data.groupby('Name').agg({'CVE': lambda x: ','.join(set(x)),
                                    'CVSS v2.0 Base Score': 'first',
                                    'CVSS v3.0 Base Score': 'first',
                                    'Risk':'first',
                                    'Host':'first',
                                    'Protocol':'first',
                                    'Port':'first',
                                    'Synopsis':'first',
                                    'Description':'first',
                                    'Solution':'first',
                                    'See Also':'first',
                                    'MSKB':'first',
                                    'Metasploit':'first',
                                    'Plugin Output':'first',
                                    # add any other columns you want to keep
                                    }).reset_index()
        # Sorting of data on the basis of Risk Severity
        unique_df = unique_df.replace(to_replace='Low', value='ZZZ')
        unique_df = unique_df.sort_values('Risk')
        unique_df = unique_df.replace(to_replace='ZZZ', value='Low')
        unique_df = unique_df.fillna(' ')
        myData = unique_df.values

        return render_template('report.html', myData=myData)
    except Exception as e:
        flash("Please upload CSV file again", "error")
        return redirect(url_for("dashbord"))

@app.route('/dwndata', methods=['POST'])
@login_required
def download_data():
    filename = os.path.join(app.config['UPLOAD_FOLDER'], 'one.csv')

        # to read the csv file using the pandas library
    data = pandas.read_csv(filename, header=0)

        # Check whether CSV file is empty or not
    data_count = list(data)
    row_count = len(data)
    if row_count == 0:
        flash("CSV must contain 1 row",'error')
        return redirect(url_for('dashbord'))

        # filter data
    data = data.filter(['CVE', 'CVSS v2.0 Base Score', 'CVSS v3.0 Base Score', 'Risk', 'Host', 'Protocol',
                        'Port', 'Name', 'Synopsis', 'Description', 'Solution', 'See Also', 'MSKB', 'Metasploit','Plugin Output'])


        # drop row which contain None severity
    data = data.drop(data.index[data['Risk'] == 'None'])
    # Remove duplicate data from by col Name
    data['Name'] = data['Name'].astype(str)
    data['CVE'] = data['CVE'].astype(str)

    unique_df = data.groupby('Name').agg({'CVE': lambda x: ','.join(set(x)),
                                    'CVSS v2.0 Base Score': 'first',
                                    'CVSS v3.0 Base Score': 'first',
                                    'Risk':'first',
                                    'Host':'first',
                                    'Protocol':'first',
                                    'Port':'first',
                                    'Synopsis':'first',
                                    'Description':'first',
                                    'Solution':'first',
                                    'See Also':'first',
                                    'MSKB':'first',
                                    'Metasploit':'first',
                                    'Plugin Output':'first',
                                    # add any other columns you want to keep
                                    }).reset_index()
        # Sorting of data on the basis of Risk Severity
    unique_df = unique_df.replace(to_replace='Low', value='ZZZ')
    unique_df = unique_df.sort_values('Risk')
    unique_df = unique_df.replace(to_replace='ZZZ', value='Low')
    unique_df = unique_df.fillna(' ')
    myData = unique_df.values
    myData = pandas.DataFrame(myData)
    #os.remove(os.path.join(app.config['UPLOAD_FOLDER'], 'one.csv'))
    csv_string = myData.to_csv(index=False)
    #    Create a response with the CSV data and appropriate headers for file download
    response = make_response(csv_string)
    response.headers['Content-Disposition'] = 'attachment; filename=my_dataframe.csv'
    response.headers['Content-type'] = 'text/csv'

    return response

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return render_template('dashbord.html')
    else:
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('dashbord'))
        return render_template('login.html', form=form)
    
#this register
@app.route('/registration', methods=['GET','POST'])
def registration():
    if current_user.is_authenticated:
        return render_template('dashbord.html')
    else:
        form = RegistrationForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))    
        return render_template('registration.html', form=form)

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
