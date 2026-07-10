# newforensicprogram???
using new found skills of SQL, hayabusa, pandas, python, ASCII, Json to create a threat detector

# GREETINGS (7/10/26) ʕ•ﻌ•ʔ
Today begins the day of working on a program for threat hunting! I think its really fun, and once you notice the signs it gets a lot easier. However, after a while, it seems like it gets repetiative, and you start to miss things! THEREFORE, i decided to combine a whole bunch of languages and existing programs to create a mini threat hunter, that hopefully with time can actually be used. I created a "windows event log" using json, and im just sort of having ai just come up with a whole bunch, some benign, and some malcious so i wont be able to recongize them. 

# What is this progam called? ʕ•ﻌ•ʔ

I really like my username, i think its very unique and has a ring to it. So the program is called TAHELEGONUS, and its centered around Pandas, Json, Python, with a inspiration from Hayabusa. Because the basis of the code is Pandas, i decided to call the engine teddybear, becasue it uses Pandas, but its not the single method of coding. I plan to utilize alot of differnt methods, as i think it would be a really fun project! 


# Loading Screen - tahelegonus.py ʕ•ﻌ•ʔ

This part took me 8 hours to do, but it was so fun! i feel like it needs to be ajsuted a little so depending on terminal size it adjusts, but atleast i got the basic code down for it. for the little bear image, i found some ASCII resources, and some guides to help make the ASCII easier to make while coding! I think it turned out well! I had a lot of fun using Python functions for the spinners. i didnt even know that was a thing untill today, and its very cool. its my favorite part for sure. 

#  Intial databse for Json files - pshunter.py ʕ•ﻌ•ʔ
This is the intial set of of the events for the database using SQL. This file is 100% a work in progress due to me finding out new detection tehcniques i can add more to the event logs.Eventually i want to be able to take a file and import it and then apply it to the program. I inputed the code for it somewhere and maybe commented it out so i wouldnt forget how i wrote it. 

# scaryevent.json ʕ•ﻌ•ʔ

I wanted to make sure that the code actually runs, so i started off with just event_ids, users, and timestamp, most recongizable threat artifacts. But as i did further research, i saw that i could add alot more from the windows logs to extract for threats. I like a chanllenge, so as i worked i added more and more attributes to the database the can be pulled from the event logs i created. So this will need to get updated a whole bunch for sure! But im excited to add some more generated events for practice too! 


# pshunteralaysis.py (just realized i mispelled analysis) ʕ•ﻌ•ʔ
So this my intial file for all my code for detection/analysis. It is very unorganized right now, and needs to be debugged, but i plan to sort of make a file for every specfic instance for each of the attributes, but it into a database, and whenver you load the program up,it should bring up very specfic details. Right now, its all over the place and certainly needs to be deubugged and formatted correctly! i think i have some pretty good code in here, espeucally sunce i used some resoruces to specfically spot out certain types of atrributes in event logs. When i finish up the intial analysis databse, it will be alot of fun to see how it gets transformed. 

# UPDATES??

i will update the program literally everyday, and as i do, ill keep the old versions, and i have labled these firsts ones as v1.0.0. So if you see that the new files are in a folder called v1.0.1, you know ive been coding away!
