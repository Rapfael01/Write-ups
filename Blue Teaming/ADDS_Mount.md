# Introduction

As part of my journey to better understanding Windows Active Directory in order to grow as a Red Teamer, I decided to do this little excercise on ADDS. By approaching the creation of ADDS, I aim to better understand the possible logic of organizations who create these systems and the possible flaws that may come along the way.

## Part 1: Preparation

We will start off from a freshly installed Windows Server 2019 VM.
![image](https://github.com/Rapfael01/Write-ups/assets/70867743/64698990-41c6-4735-bf8f-8b2defbfaca6)

We will go into our Server Manager and Install ADDS. We click **Manage** on the top right and click **Add roles or features**. To make things simple, we choose **Role-based or feature-based installation**.
![image](https://github.com/Rapfael01/Write-ups/assets/70867743/a15bda6c-8012-41c6-a476-69487a6cfe35)

We choose the local server from the pool.
![image](https://github.com/Rapfael01/Write-ups/assets/70867743/0529330d-d6e1-4e2f-989c-15d003157706)

Next, we choose the roles we will install. The most important for the purposes of this lab will be ADDS.
![image](https://github.com/Rapfael01/Write-ups/assets/70867743/dfc38ef9-7a85-4947-b2ea-8b0cc684042d)

The features should be automatically selected based on the roles we picked, so we will skip that and install/restart.

Next, we will convert this server into a DC. Back in our Server Manager, we will click on the flag next to the previously clicked Manage button and we'll click on the **Promote this server to a Domain Controller** hyperlink.

We'll add a new forest which we'll call **ADDSLab.com**.
![image](https://github.com/Rapfael01/Write-ups/assets/70867743/414d3893-beb4-4365-8889-64a9ef404b36)

We set the password for the DC Options, we won't be making any DNS Changes for this occasion, we'll leave the NetBIOS domain name and AD paths as default. 

![image](https://github.com/Rapfael01/Write-ups/assets/70867743/b6eb15ac-4ec0-4271-825f-bed4ec1c9c9e)
After this, we can click on install and begin the promotion.

## Part 2: Creatings OU's for each department

Next up, we will create Organizational Units for each of the departements in the company. We will use IT, HR, Sales, Management and Finance for this example. In order to create an OU, we go into **Active Directory Users and Computers**, select our Domain, click on Action->New->Organizational Unit and click.
![image](https://github.com/Rapfael01/Write-ups/assets/70867743/85a04ab0-5348-455c-92ed-19725fca50c6)

