import json
import graphviz
import pandas as pd
from matplotlib import pyplot as plt
from sklearn import linear_model, tree
from sklearn.metrics import mean_squared_error, accuracy_score
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import export_graphviz
from subprocess import call


import os
os.environ["PATH"] += os.pathsep + 'C:/Program Files/Graphviz/bin' # cambiar ruta por la que tengas instalado el graphviz

with open('jsons/users_IA_clases.json', 'r') as file:
    train = json.load(file)

usernames = []
phishingRecived = []
phishingClicked = []
vulnerable = []
clickProbability = []

for user in train["usuarios"]:
    usernames = usernames + [user["usuario"]]
    phishingRecived = phishingRecived + [user["emails_phishing_recibidos"]]
    phishingClicked = phishingClicked + [user["emails_phishing_clicados"]]
    vulnerable = vulnerable + [user["vulnerable"]]

    if user["emails_phishing_recibidos"] != 0:
        clickProbability.append(user["emails_phishing_clicados"] / user["emails_phishing_recibidos"])
    else:
        clickProbability.append(0.000000000)


dfInfo = pd.DataFrame()
dfVuln = pd.DataFrame()

dfInfo["phishingRecived"] = phishingRecived
dfInfo["phishingClicked"] = phishingClicked
dfVuln["vulnerable"] = vulnerable

dfProbability = pd.DataFrame (clickProbability, columns=['probability'])
dfTrain = dfInfo.join(dfProbability)

# ---------------- REGRESION LINEAL ------------------- #

dfTrain = dfTrain.to_numpy()

# Use only one feature
dfTrain = dfTrain[:, np.newaxis, 2]

# Split the data into training/testing sets
dfTrain_X_train = dfTrain[:-20]
dfTrain_X_test = dfTrain[-20:]

# Split the targets into training/testing sets
dfVuln_Y_train = dfVuln[:-20]
dfVuln_Y_test = dfVuln[-20:]

# Create linear regression object
regr = linear_model.LinearRegression()

# Train the model using the training sets
regr.fit(dfTrain_X_train, dfVuln_Y_train)
print(regr.coef_)

# Make predictions using the testing set
vulnPrediction = regr.predict(dfTrain_X_test)
print(vulnPrediction)

# The mean squared error
print("Mean squared error: %.2f" % mean_squared_error(dfVuln_Y_test, vulnPrediction))

# Plot outputs
plt.scatter(dfTrain_X_test, dfVuln_Y_test, color="dodgerblue")
plt.plot(dfTrain_X_test, vulnPrediction, color="lightpink", linewidth=3)
plt.xlabel("ClickProbability")
plt.ylabel("Vulnerable")
plt.xticks(())
plt.yticks(())
plt.show()

# ---------------- DECISION TREE ------------------- #

clf = tree.DecisionTreeClassifier()
clf.fit(dfTrain_X_train, dfVuln_Y_train)

print("Decision tree .predict", clf.predict(dfTrain))
vulnPrediction = clf.predict(dfTrain_X_test)
print("Accuracy: %.2f" % accuracy_score(dfVuln_Y_test, vulnPrediction))

#Print plot
dot_data = tree.export_graphviz(clf, out_file=None)
graph = graphviz.Source(dot_data)
graph.render("ej6/tree_graph_render")
dot_data = tree.export_graphviz(clf, out_file=None,
                     filled=True, rounded=True,
                    special_characters=True)
graph = graphviz.Source(dot_data)
graph.render("ej6/tree.gv", view=True).replace('\\', '/')

# ---------------- RANDOM FOREST ------------------- #

clf = RandomForestClassifier(max_depth=2, random_state=0, n_estimators=10)
clf.fit(dfTrain_X_train, dfVuln_Y_train.values.ravel())
print("Random forest .predict", clf.predict(dfTrain))
print(str(dfTrain_X_train[0]) + " " + str(dfVuln_Y_train.values.ravel()[0]))

for i in range(len(clf.estimators_)):
    estimator = clf.estimators_[i]
    export_graphviz(estimator,
                    out_file='forest.dot',
                    rounded=True, proportion=False,
                    precision=2, filled=True)
    call(['dot', '-Tpng', 'forest.dot', '-o', 'forest' +str(i)+ '.png', '-Gdpi=600'])