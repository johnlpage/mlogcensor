from __future__ import print_function
import sys
import re

#MongoDB log redactor
#Version 1.0

#Print to standard error not stadard output
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


timestamp_pattern = r"([0-9T:\+\.\-]{28})"
level_pattern = r"([IEW])"
logarea_pattern = r"(COMMAND|NETWORK|REPL|ACCESS|WRITE|QUERY|ASIO|FTDC|CONTROL|INDEX|JOURNAL|STORAGE)"
connection_no_pattern  = r"\[(.*?)\]"
optype_pattern = r"([a-zA-Z]*)"
rest_of_line_pattern = r"(.*)$"

pattern = "^%s +%s +%s +%s +%s +%s" % (timestamp_pattern,level_pattern,
	                                logarea_pattern,connection_no_pattern,
	                                 optype_pattern,rest_of_line_pattern)


# Define the lines we are happy to output and their redaction
#This code doesnt remote but rather parses and constructs.

approved_outputs = {
"NETWORK_end" : (r"^connection.*\(([0-9]*) connections? now open\)",
                  "connection 0.0.0.0:12345 (%s connections now open)"),

"NETWORK_connection" : (r"^accepted from.*\(([0-9]*) connections? now open\)",
                         "accepted from 0.0.0.0:12345 (%s connections now open)"),

"NETWORK_SocketException" : (r"^(.*?)server", "%s"),
"NETWORK_waiting" : (r"^(.*)","%s"),
"NETWORK_removing" : (r"^(.*)","%s"),
"NETWORK_Starting" : (r"^(.*)","%s"),
"NETWORK_addr" : (r"^(.*)","%s "),
"ACCESS_Unauthorized" : (r"^(.*?command)", "%s {field:value}"),
"NETWORK_closing" : (r"^(.*)","%s"),
#This one we keep the IP adresses as they are internal IPs
"NETWORK_Failed" : (r"^(.*)","%s"),
"WRITE_remove" : (r"^.*? +.*(ndeleted.*)$",
                     "database.collection query: { field: value } %s"),

"WRITE_update" : (r"^.*? +.*?(nscanned.*|keysExamined.*)$",
                     "database.collection query: { field: value } %s"),

"WRITE_insert" : (r"^.*? +.*(ninserted.*)$",
                     "database.collection query: { field: value } %s"),

"COMMAND_getmore" : (r"^.*? +.*(cursorid.*)$",
                     "database.collection query: { field: value } %s"),

"COMMAND_command" : (r"^.*? +(command: .*?) .*(keyUpdates.*)$",
                     "database.collection %s { field : value } %s"),

"COMMAND_query" : (r"^.*? +.*(planSummary.*)$",
                     "database.collection  { field : value } %s"),
"COMMAND_dropDatabase" : (r"^.*? +.*?(.*)$",
                     "database.collection %s"),
"QUERY_killcursors" : (r"^(.*)$","%s"),

"QUERY_getmore" : (r"^.*? +.*(cursorid.*)$",
                     "database.collection query: { field: value } %s"),
"QUERY_query" : (r"^.*? +.*(planSummary.*)$",
                     "database.collection  { field : value } %s"),
#Index build always leaks field name so we only show a bit
"INDEX_build" : (r"^index +(.*?) +.*?(scanned.*)?",
                  "index %s db.collection %s"),

"ACCESS_Successfully" : (r"^authenticated",
	                      "as principal user on database")


}



linere = re.compile(pattern)
unknown_format_count = 0
match_count = 0

def process_detail(groups,line_processor):
	match_pattern = line_processor[0]
	redact_template = line_processor[1]
	match_re = re.compile(match_pattern)
	captures = match_re.match(groups[5])
	if captures == None:
		#return "REDACTED_PROCESSOR_DOESNT_MATCH ("+groups[5]+")" #Cannot identify format
		return None
	else:
		return redact_template % captures.groups()

def process_logline(groups):
	#print(groups)
	logarea = groups[2]
	optype = groups[4]
	line_processor = approved_outputs.get(logarea+"_"+optype,None)
	if line_processor == None:
		#We do not have a way to process this op
		#return "REDACTED_NO_PROCESSOR ("+groups[5]+")"
		return None
	else:
		return process_detail(groups,line_processor)




if len(sys.argv) != 2:
	eprint ("Usage: python logredact.py <logfile>")
	sys.exit(1)

for logline in open(sys.argv[1],'r'):
	o = linere.match(logline)
	if o != None:
			groups = o.groups()
			#Internal events known to have no user data
			if  groups[2] in ("REPL","STORAGE","JOURNAL","CONTROL","FTDC","ASIO"):
				match_count += 1
				print(" ".join(groups[:3])+" ["+groups[3]+"] "+groups[4]+ " "+groups[5])
			else:
				redacted = process_logline(groups)
				if redacted != None:
					match_count += 1

					print(" ".join(groups[:3])+" ["+groups[3]+"] "+groups[4]+ " "+redacted)
				else:
					unknown_format_count += 1
	else:
			#Do NOT print any lines we can't positively identify
			unknown_format_count += 1


eprint("matched: %d unknown: %d\n" % (match_count,unknown_format_count) )