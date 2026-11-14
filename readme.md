# **Basic Summary of the Different Scored Components**

## **We are the Blue Team: IT & Security of Closed AI**

**Context:** Closed AI is in the news with Legal Issues. Previous IT team all resigned, and we are the new hires.

### **Our Responsibilities:**

* **Understand our current tech stack:**
* Firewall (OPNSense)
* Windows Server 2025 (Primary Domain Controller)
* Windows Server 2022 (Web Server
* Ubuntu (database/app Server)
* Rocky (Mail server)


* **Accommodate any and all requests from Managment (our forensics questions which are called "injects" in this comp)**
* these will be on a timed-basis, basically drop everything and answer immediately
* requires formal writing addressing issues ranging various topics including the following
* briefing/write-up on red team incident
* standing up/deploying new services
* "onboarding" new employees ( i think this means just write ups on how our current tech stack works etc.)




* **Score points via:**
* keeping services operational
* completing "injects"
* incident response and recovery to red team behaviors
* unique sponsor challenges worth up to 2000 points, evaluat4ed in its own prize bracket revealed on comp day



---

### **Who and what is the Red Team:**

* **Competition Staff will act as the red team (they will allegedly only start extremely active interventions around 3 hours into the competition)**
* will scan and map our network
* try to establish persistent mechanisms of access
* our job to lock them out


* disrupt company operations



---

### **Who and what is the White Team:**

* **Purdue BTaP officers will manage this team**
* they will write and deliver the injects
* judge the Blue Team's response to injects
* manage the scoring engine
* answer tickets



---

## **Competition Software:**

* **To access the VM's and images, a website interface called Guacamole will be used:** [https://console.purdueblue.team/](https://console.purdueblue.team/)
* only one connection per VM
* no clipboards or file transfers


* **The platform Quotient will be used to submit inject responses and view current scores:** [https://quotient.purdueblue.team/](https://quotient.purdueblue.team/)
* acts as the scoring engine
* each service is scored using 10 recent checks
* will display injects as card, with a specific task and **DUE DATE/TIME**
* can include multiple parts found as an email in the mailserver


* Responses to injects will always be submitted as PDFs, named Incident Reports (self explanatory)
* Password change requests can be made here to change the entire team credentials


* **All competition announcements will be made on Discord**
* **A ticketing system will be deployed on a web site to reach the White Team as well for troubleshooting:** [https://tickets.purdueblue.team/](https://tickets.purdueblue.team/)
* **Three ticket types that result in penalties:**
* **Reverting machines** will cause a loss of 200 points, but may be still beneficial for getting rid of accruing point penalties from a broken services
* **Scoring Consultation** will give use a reason why a Quotient check isn't giving us points, at the cost of 100 points
* **Help with infrastructure issues or general questions** have 0 points penalty




* **Vague, but apparently the mail server on the Rocky Linux machine will be used to receive injects and to communicate using the chat servers as well?? (need clarification, will prbly ask in the questions channel in the discord server)**
* We will have a shared mailbox per team called **itsops@closedai.com**
* the service used is called Roundcube, at **mail.closedai.com** only viewable from the windows server machine


* **To sign in as our team, the following domain will be used:** [https://auth.purdueblue.team/](https://auth.purdueblue.team/)

---

## **Topology:**

**Wide Area Network:** (local ip, public ip)

* **cai-fw01:** OPNsense Firewall (`10.42.0.1`, `10.100.N.1`)
* very sensitive and routing changes can making services inoperable


* **Local Area Network:** `10.42.0.0/24`
* **CAI-DC01:** Server 2025 DC (`10.42.0.10`, `10.100.N.10`)
* NETBIOS: **CLOSEDAI**
* Runs DNS
* **DO NOT TOUCH SPLUNK**


* **CAI-WEB01:** Server 2022 Web Server (`10.42.0.20`, `10.100.N.20`)
* **cai-db01:** Ubuntu DB/APP Server (`10.42.0.30`, `10.100.N.10`)
* **cai-mail01:** Rocky MAIL Server (`10.42.0.40`, `10.100.N.40`)



---

## **Critical Services:**

* HTTP
* HTTPS
* SMTP
* IMAP/Webmail
* DNS
* SMB
* FTP
* SSH
* RDP
* "database" (generic idk why)
* "Chat" (generic idk why)

---
