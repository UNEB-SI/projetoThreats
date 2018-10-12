from tkinter import filedialog
from tkinter import *
import tkinter as tk
import pandas as pd
import os
from sklearn import preprocessing
from sklearn.tree import DecisionTreeClassifier, export
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
import numpy as np
import graphviz
from kmodes.kprototypes import KPrototypes
from xml.etree import ElementTree as et
from sklearn.metrics import confusion_matrix, accuracy_score

class View(object):

    def __init__(self, master=None):
        self.root = master
        self.root.title('Correlação de Evento e Análise de Vulnerabilidade')
        self.root.geometry('1000x1000+200+20')
        descricao = Label(self.root,
                          text="Projeto de pesquisa para conclusão do curso de sistema de informação")  # cria um label com o texto especificado
        descricao.pack()
        self.menu()

    def menu(self):

        menu = tk.Menu(self.root)
        # filemenu = Menu(menu)
        filemenu = tk.Menu(menu, tearoff=0)
        # filemenu.add_command(label="Sair", command=self.root.quit)
        # menu.add_cascade(label="Arquivo", menu=filemenu)

        # menu.add_cascade(label="File", menu=filemenu)
        filemenu.add_command(label="New", command=self.NewFile)
        filemenu.add_command(label="Open", command=self.OpenFile)
        filemenu.add_command(label="About", command=self.About)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)
        menu.add_cascade(label="File", menu=filemenu)

        self.root.config(menu=menu)

    def NewFile(self):
        print("New File!")

    def OpenFile(self):
        nomeArquivo = filedialog.askopenfilename(initialdir="", title="Select file", filetypes=[("all files", ".*")])
        with open(nomeArquivo, 'r', encoding='utf-8') as arquivo:
            df = pd.read_csv(arquivo)

            # df['Receive Time'] = pd.to_datetime(df['Receive Time'])

            for i in range(df['Destination User'].count()):
                destino = df['Destination User'][i]
                origem = df['Source User'][i]
                enderecoOrigem = df['Source address'][i]
                enderecoDestino = df['Destination address'][i]

                if type(destino) == float:
                    df.loc[i, 'Destination User'] = 'any'

                if type(origem) == float:
                    df.loc[i, 'Source User'] = 'any'

                if type(enderecoOrigem) == float:
                    df.loc[i, 'Source address'] = 'any'

                if type(enderecoDestino) == float:
                    df.loc[i, 'Destination address'] = 'any'

            results = {
                'Receive Time': df['Receive Time'],
                'Source Address': df['Source address'],
                'Destination Address': df['Destination address'],
                'Source Zone': df['Source Zone'],
                'Destination Zone': df['Destination Zone'],
                'Source Port': df['Source Port'],
                'Destination Port': df['Destination Port'],
                'Threat/Content Name': df['Threat/Content Name'],
                'Severity': df['Severity'],
                'thr_category': df['thr_category'],
                'Destination User': df['Destination User'],
                'Source User': df['Source User'],
                'Rule': df['Rule'],
                'Application': df['Application'],
                'Direction': df['Direction']
            }

            arquivoOutput = 'C:/Users/stephl05/Desktop/projetoAplicativo/trainThreats.csv'
            stringP = pd.DataFrame(results, columns=['Receive Time', 'Source Address',
                                                     'Destination Address', 'Source Zone', 'Destination Zone',
                                                     'Source Port', 'Destination Port', 'Threat/Content Name',
                                                     'Severity', 'thr_category', 'Destination User', 'Source User',
                                                     'Rule', 'Application', 'Direction'])

            stringP['Date'], stringP['Time'] = zip(*stringP['Receive Time'].map(lambda x: x.split(' ')))
            stringP['Date'] = pd.to_datetime(stringP['Date'])
            stringP['Time'] = pd.to_datetime(stringP['Time'])

            # stringP['Time'] = stringP['Receive Time'].dt.time
            # stringP['Date'] = stringP['Receive Time'].dt.date

            stringP = stringP.drop(['Receive Time'], axis=1)
            stringP.to_csv(arquivoOutput)
            self.padronizarDados(stringP)

    def About(self):
        print("This is a simple example of a menu")

    def classificador(self, file):

        le = preprocessing.LabelEncoder()
        previsores = file.iloc[:, 0:17].values
        classes = file.iloc[:, 17].values
        classes = classes.astype(str)

        previsores[:, 0] = le.fit_transform(previsores[:, 0])
        previsores[:, 1] = le.fit_transform(previsores[:, 1])
        previsores[:, 2] = le.fit_transform(previsores[:, 2])
        previsores[:, 3] = le.fit_transform(previsores[:, 3])
        previsores[:, 4] = le.fit_transform(previsores[:, 4])
        previsores[:, 5] = le.fit_transform(previsores[:, 5])
        previsores[:, 6] = le.fit_transform(previsores[:, 6])
        previsores[:, 7] = le.fit_transform(previsores[:, 7])
        previsores[:, 8] = le.fit_transform(previsores[:, 8])
        previsores[:, 9] = le.fit_transform(previsores[:, 9].astype(str))
        previsores[:, 10] = le.fit_transform(previsores[:, 10].astype(str))
        previsores[:, 11] = le.fit_transform(previsores[:, 11])
        previsores[:, 12] = le.fit_transform(previsores[:, 12])
        previsores[:, 13] = le.fit_transform(previsores[:, 13])

        previsores[:, 14] = pd.to_datetime(previsores[:, 14]).astype('int64')
        max_a = file['Time'].max()
        min_a = file['Time'].min()
        min_norm = -1
        max_norm = 1
        previsores[:, 14] = (file['Time'] - min_a) * (max_norm - min_norm) / (max_a - min_a) + min_norm

        previsores[:, 15] = pd.to_datetime(previsores[:, 15]).astype('int64')
        max_a_ = file['Date'].max()
        min_a_ = file['Date'].min()
        min_norm_ = -1
        max_norm_ = 1
        previsores[:, 15] = (file['Date'] - min_a_) * (max_norm_ - min_norm_) / (max_a_ - min_a_) + min_norm_

        print(previsores[:, 14])
        print(previsores[:, 15])
        exit()

        scaler = preprocessing.StandardScaler()
        previsores = scaler.fit_transform(previsores)
        previsores_treinamento, previsores_teste, classe_treinamento, classe_teste = train_test_split(previsores,
                                                                                                      classes,
                                                                                                      test_size=0.25,
                                                                                                      random_state=0)
        classificador = DecisionTreeClassifier(criterion="entropy", random_state=0, max_depth=None, min_samples_leaf=5)
        classificador.fit(previsores_treinamento, classe_treinamento)
        # print(classificador.feature_importances_)
        previsoes = classificador.predict(previsores_teste)

        precisao = accuracy_score(classe_teste, previsoes)
        matriz = confusion_matrix(classe_teste, previsoes)

        print(precisao)
        print(matriz)

        dot_data = export.export_graphviz(classificador,
                                          out_file=None,
                                          feature_names=['Source Address',
                                                         'Destination Address',
                                                         'Source Zone', 'Destination Zone',
                                                         'Source Port', 'Destination Port',
                                                         'Threat/Content Name', 'Severity',
                                                         'thr_category', 'Destination User', 'Source User', 'Rule',
                                                         'Application', 'Direction', 'Date', 'Hours', 'Clusters'],
                                          class_names=classes,
                                          filled=True, rounded=True,
                                          leaves_parallel=True,
                                          special_characters=True)
        graph = graphviz.Source(dot_data)
        graph.render("file", view=True)

    def padronizarDados(self, file):

        # style.use("ggplot")
        caminho = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Ameaças/Novos/trainThreats.csv'
        colors = ['b', 'orange', 'g', 'r', 'c', 'm', 'y', 'k', 'Brown', 'ForestGreen']
        # Data points with their publisher name,category score, category name, place name
        #category = np.genfromtxt(caminho, dtype=str, delimiter=',', skip_header=1)[:, 9]  # categoria
        #severity = np.genfromtxt(caminho, dtype=str, delimiter=',', skip_header=1)[:, 8]  # severidade
        X = np.genfromtxt(caminho, dtype=object, delimiter=',', skip_header=1)[:, 1:]

        kproto = KPrototypes(n_clusters=5, init='Cao', verbose=2)
        clusters = kproto.fit_predict(X, categorical=[0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

        '''plt.scatter(X[clusters == 0, 8], X[clusters == 0, 9], c='red', alpha=0.8, s=30, label='Cluster 0')
        plt.scatter(X[clusters == 1, 8], X[clusters == 1, 9], c='orange', alpha=0.8, s=30, label='Cluster 1')
        plt.scatter(X[clusters == 2, 8], X[clusters == 2, 9], c='green', alpha=0.8, s=30, label='Cluster 2')
        plt.scatter(X[clusters == 3, 8], X[clusters == 3, 9], c='blue', alpha=0.8, s=30, label='Cluster 3')
        plt.scatter(X[clusters == 4, 8], X[clusters == 4, 9], c='purple', alpha=0.8, s=30, label='Cluster 4')
        plt.xlabel('Severidade')
        plt.ylabel('Categoria')
        plt.legend()
        plt.show()'''

        file['Clusters'] = clusters


        # Print cluster centroids of the trained model.
        print(kproto.cluster_centroids_)
        # Print training statistics
        print(kproto.cost_)
        print(kproto.n_iter_)

        self.lerXML(file)

    def lerXML(self, file):

        file_name = "C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/Ameaças/unib/running-config.xml"
        full_file = os.path.abspath(os.path.join('data', file_name))

        dom = et.parse(full_file)
        rules = dom.findall('devices/entry/vsys/entry/rulebase/security/rules')
        rulesEntry = dom.findall('devices/entry/vsys/entry/rulebase/security/rules/entry')

        self.idAmecaFalsoPositivo(file, rules, rulesEntry)

    def idAmecaFalsoPositivo(self, file, rules, rulesEntry):
        regras = []

        for entry in rules:
            for child in entry:
                regras.append(child.attrib)

        for i, item in enumerate(rulesEntry):
            regras[i]['to'] = [item.find("to")]
            regras[i]['from'] = [item.find("from")]
            regras[i]['source'] = [item.find("source")]
            regras[i]['destination'] = [item.find("destination")]
            regras[i]['source-user'] = [item.find("source-user")]
            regras[i]['category'] = [item.find("category")]
            regras[i]['application'] = [item.find("application")]
            regras[i]['service'] = [item.find("service")]
            regras[i]['action'] = [item.find("action")]
            regras[i]['to_'] = []
            regras[i]['from_'] = []
            regras[i]['source_'] = []
            regras[i]['destination_'] = []
            regras[i]['source-user_'] = []
            regras[i]['category_'] = []
            regras[i]['application_'] = []
            regras[i]['service_'] = []

            for to in regras[i]['to']:
                for node1 in to.getiterator():
                    regras[i]['to_'].append(node1.text)

            for from_ in regras[i]['from']:
                for node2 in from_.getiterator():
                    regras[i]['from_'].append(node2.text)

            for source in regras[i]['source']:
                for node3 in source.getiterator():
                    regras[i]['source_'].append(node3.text)

            for destination in regras[i]['destination']:
                for node4 in destination.getiterator():
                    regras[i]['destination_'].append(node4.text)

            for source_user in regras[i]['source-user']:
                for node5 in source_user.getiterator():
                    regras[i]['source-user_'].append(node5.text)

            for category in regras[i]['category']:
                for node6 in category.getiterator():
                    regras[i]['category_'].append(node6.text)

            for app in regras[i]['application']:
                for node7 in app.getiterator():
                    regras[i]['application_'].append(node7.text)

            for service in regras[i]['service']:
                for node8 in service.getiterator():
                    regras[i]['service_'].append(node8.text)

        tamRegras = len(regras)
        for index, row in file.iterrows():
            for i in range(tamRegras):
                if row["Rule"] == regras[i]['name']:
                    if row["Severity"] != "critical" and row["Severity"] != "high":
                        if ((row["Source Zone"] != "CORPORATIVA") and (row['Destination Zone'] == "CORPORATIVA") and
                                (row["Application"] in regras[i]['application_']) and (
                                        row['Source User'] in regras[i]['source-user_']) and
                                        (row["Source Address"] != "any") or (row['Destination Zone'] != "any")):
                            file.loc[index, 'False Positive'] = 'yes' #equivale a sim
                        else:
                            file.loc[index, 'False Positive'] = 'no'
                    else:
                        file.loc[index, 'False Positive'] = 'no' #equivale a nao

        arquivoOutput = 'C:/Users/Teste/Desktop/10 semestre/tcc2/Arquivos de Logs/Arquivos de Logs/new.csv'
        file.to_csv(arquivoOutput)
        self.classificador(file)


root = Tk()
View(root)

root.mainloop()