import json
import pandas as pd
import sqlite3
import plotly
from flask import Flask, render_template, request, redirect, url_for
import hashlib
import requests
import plotly.express as px
import plotly.graph_objects as go

con = sqlite3.connect('database.db', check_same_thread=False)
cursorObj = con.cursor()

sqlconnection = sqlite3.connect('Login.db', check_same_thread=False)
cursorLogin = sqlconnection.cursor()

app = Flask(__name__, template_folder='templates', static_folder='static')


# -- EJERCICIO 5 · LOGIN Y REGISTRO --
def initLoginDB():
    cursorLogin.execute("CREATE TABLE Users (Username text, Password text, Email text, PRIMARY KEY (Username))")
    sqlconnection.commit()

@app.route("/")
def loginPage():
    return render_template("login.html")

@app.route("/", methods = ["POST"])
def login():
    user = request.form['Username']
    passwd = request.form['Password']
    currentHash = hashlib.sha512(passwd.encode('utf-8')).hexdigest()

    query1 = "SELECT Username, Password FROM Users WHERE Username = '{user}' AND Password = '{currentHash}'".format(user=user, currentHash=currentHash)

    rows = cursorLogin.execute(query1)
    rows = rows.fetchall()

    # Si se introducen nombres de usuario o contraseñas erroneas te redirige de nuevo al login
    try:
        if len(rows) == 1:
            return render_template("Home.html")
        else:
            return render_template("/register")
    except:
        return redirect('/')


@app.route("/register", methods=["GET","POST"])
def registerpage():
    if request.method == "POST":
        userReg = request.form['UsernameReg']
        passwdReg = request.form['PasswordReg']
        emailReg = request.form['EmailReg']

        currentPassword = hashlib.sha512(passwdReg.encode('utf-8')).hexdigest()

        cursorLogin = sqlconnection.cursor()

        #En caso de que ya exista el usuario te redirige de nuevo al registro
        try:
            query1 = "INSERT INTO Users VALUES('{userReg}', '{currentPassword}','{emailReg}')".format(userReg=userReg, currentPassword=currentPassword, emailReg=emailReg)
            cursorLogin.execute(query1)
        except:
            return redirect('/register')

        sqlconnection.commit()
        return redirect("/")
    return render_template("register.html")


# -- EJERCICIO 2 --
@app.route("/home")
def index():
    return render_template('Home.html')

@app.route("/criticUsers", methods=["GET", "POST"])
def top_x_critic_users():
    top = request.form.get('numero', default=10)
    if (top == ''):
        top = 10
    filelist = open("passwords.txt").read().splitlines()
    dataframe = pd.read_sql_query("SELECT username, phishingEmails, clicKedEmails, password FROM users", con)

    userList = []
    for i in range(dataframe['password'].values.size):
        for line in filelist:
            if dataframe['password'].values[i] == hashlib.md5(line.encode('utf-8')).hexdigest():
                userList.append(dataframe['username'].values[i])

    prob = []
    for i in range(dataframe['username'].values.size):
        for j in range(len(userList)):
            if userList[j] == dataframe['username'].values[i]:
                if dataframe['phishingEmails'].values[i] == 0:
                    prob.append(0.0000000000000000)
                else:
                    prob.append(dataframe['clickedEmails'].values[i] / dataframe['phishingEmails'].values[i])

    FinalList= []
    for i in range(len(userList)):
        FinalList.append(str(prob[i]) +':'+ userList[i])


    FinalList.sort(reverse=True)
    listaFinal = FinalList[0:int(top)]
    criticUsers = []
    probCriticUsers = []

    for i in range(len(listaFinal)):
        criticUsers.append(listaFinal[i].split(":")[1])
        probCriticUsers.append(listaFinal[i].split(":")[0])


    reversedProbCriticUsers = list(reversed(probCriticUsers))
    reversedCriticUsers = list(reversed(criticUsers))
    dfProb = pd.DataFrame(reversedProbCriticUsers, columns=['Prob_criticUsers'])
    dfUsers = pd.DataFrame(reversedCriticUsers, columns=['criticUsers'])

    fig = px.bar(y=dfProb['Prob_criticUsers'], x=dfUsers['criticUsers'], labels=dict(x="Users", y="Probability"))
    a = plotly.utils.PlotlyJSONEncoder
    graphJSON = json.dumps(fig, cls=a)

    # -- EJERCICIO 3 --
    df_more_50 = pd.read_sql_query(
    "SELECT username,phone,province,totalEmails,phishingEmails,clickedEmails FROM users where clickedEmails > users.phishingEmails/2",con)

    df_less_50 = pd.read_sql_query(
    "SELECT username,phone,province,totalEmails,phishingEmails,clickedEmails FROM users where clickedEmails <= users.phishingEmails/2",con)
    return render_template('Critic-Users.html', graphJSON=graphJSON, clickmore=df_more_50.to_html(), clickless=df_less_50.to_html())

@app.route("/vulnerableWebs", methods=["GET", "POST"])
def top_x_vulnerable_webs():

    top = request.form.get('numero', default=10)
    if (top == ''):
        top = 10

    dfPolicies = pd.read_sql_query("SELECT url, cookies, warning, dataProtection FROM legal", con)

    dfPolicies['result'] = dfPolicies['cookies'] + dfPolicies['warning'] + dfPolicies['dataProtection']  # Sumamos los valores de las columnas y lo guardamos en una llamada result
    dfPolicies = dfPolicies.sort_values('result').head(int(top))  # Ordenamos y sacamos las 5 primeras

    fig = go.Figure(data=[
        go.Bar(name='Cookies', x=dfPolicies['url'], y=dfPolicies['cookies'], marker_color='mediumturquoise'),
        go.Bar(name='Warning', x=dfPolicies['url'], y=dfPolicies['warning'], marker_color='plum'),
        go.Bar(name='DataProtection', x=dfPolicies['url'], y=dfPolicies['dataProtection'], marker_color='mediumpurple')
    ])

    a = plotly.utils.PlotlyJSONEncoder
    graphJSON = json.dumps(fig, cls=a)

    # -- EJERCICIO 4 --
    vulnWebs = requests.get('https://cve.circl.lu/api/last')
    getJson = vulnWebs.text

    dfVuln = pd.DataFrame()
    dfVuln["id"] = pd.read_json(getJson)["id"]
    dfVuln["last-modified"] = pd.read_json(getJson)["last-modified"]
    dfVuln["summary"] = pd.read_json(getJson)["summary"]

    return render_template('Vulnerable-Webs.html', graphJSON=graphJSON, vulncves=dfVuln.head(10).to_html())


# -- EJERCICIO 3 --
@app.route("/more50")
def df_spam_click_more50():
    df_more_50 = pd.read_sql_query(
    "SELECT username,phone,province,totalEmails,phishingEmails,clickedEmails FROM users where clickedEmails > users.phishingEmails/2",con)
    return render_template('More50.html', clickmore=df_more_50.to_html())

@app.route("/less50")
def df_spam_click_less50():
    df_less_50 = pd.read_sql_query(
    "SELECT username,phone,province,totalEmails,phishingEmails,clickedEmails FROM users where clickedEmails <= users.phishingEmails/2",con)
    return render_template('Less50.html', clickless=df_less_50.to_html())


# -- EJERCICIO 5 · API VIRUSTOTAL--
@app.route("/virustotal", methods=["GET", "POST"])
def virusTotal():
    ip_add = request.form.get('ip', default="8.8.8.8")
    if (ip_add == ''):
        ip_add = "8.8.8.8"
    print("Enter the API key: ")
    api_key = "955293cd06537edb5adabfbb1f39c028301bfc9564697e9c4846c394a0c563f2"
    r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/%s" % ip_add, headers={'User-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0', 'x-apikey': '%s' % api_key}).json()
    dict_web = r["data"]["attributes"]["last_analysis_results"]
    tot_engine_c = 0
    tot_detect_c = 0
    result_eng = []
    eng_name = []
    count_harmless = 0
    for i in dict_web:
        tot_engine_c = 1 + tot_engine_c
        if dict_web[i]["category"] == "malicious" or dict_web[i]["category"] == "suspicious":
            result_eng.append(dict_web[i]["result"])
            eng_name.append(dict_web[i]["engine_name"])
            tot_detect_c = 1 + tot_detect_c
    res = []
    for i in result_eng:
        if i not in res:
            res.append(i)
    result_eng = res
    if tot_detect_c > 0:
        print("The %s was rated for" % ip_add + str(result_eng)[1:-1] + " on " + str(tot_detect_c) + " engines out of " + str(tot_engine_c) + " engines. The Engines which reported this, are: " + str(eng_name)[1:-1] + ".")
    else:
        print("The IP has been marked harmless and clean by VirusTotal")
    return render_template('virustotal.html', v1=str(result_eng)[1:-1], v2=str(tot_detect_c), v3=str(tot_engine_c), v4=str(eng_name[1:-1]), v5=ip_add)


if __name__ == '__main__':
    app.run()
    initLoginDB()
    sqlconnection.close()