# Computer Security Lab Project
###
### The University of Technology
### Faculty of Engineering & Computing (FENC)
### School of Computing & Information Technology (SCIT)
###
#### Course: Computer Security
#### Course Code: CIT4020
#### Date Given: March 3, 2023
#### Date Due: April 10, 2023
###
#### Group Members:
+ Rushawn White - 2002469
+ Tori Horne - 2002633 
+ Daryn Brown - 2002414
####
### Instructions:
+ Form groups consisting of no more than four (4) students 
+ Review the following case study and perform the tasks indicated below 
+ Response submissions must be made to the respective tutor’s folder found in the Google Drive link below by the due date 
+ Unsubmitted reports will result in failure. Please note not every member of the group will
receive the same grade.

### Honeypots
You're responsible for the security of Xen Tech Limited a large IT company in Jamaica. Due to a
recent increase in cyber-attacks against the company’s webserver, the management has suggested
that you implement a system to detect and track potential attackers who are trying to break into
the network. You decide to set up a honeypot to lure attackers into revealing their tactics and
techniques.

You desire to configure the honeypot to mimic a vulnerable server that's commonly targeted by
attackers and place it on a separate network segment to prevent attackers from accessing your
production systems. You also desire to set up monitoring and logging tools to capture and
analyze all traffic to and from the honeypot.

#### Tasks: (Be as creative as you can)

1. Write a python Honeypot that listens for incoming connections on multiple ports `(22, 80,
and 443)` and logs any data received. **[30 marks]**
2. The honeypot should also include additional features such as packet capture, intrusion
detection, and alerting. **[20 marks]**
3. Write a report to share your findings to include source and destination IP addresses
captured, any intrusions detect, possible vulnerabilities attackers were targeting and alerts
etc **[10 marks]**
4. Suggest ways to properly secure the honeypot to prevent attackers from using it to attack
other systems if the organization is using only layer 2 switches. **[10 marks]**

***Bonus***
+ Simulate how you would create a VLAN in Cisco Packet Tracer to segment the Honeypot
from production systems assuming layer 2 switches are being used. **[10 marks]**

