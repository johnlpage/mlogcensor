from __future__ import print_function
import sys
import re
from pprint import pprint
#MongoDB log redactor
#Version 1.0


#Print to standard error not stadard output
def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)

def log_unredacted(line):
	unredacted_log.write(line+"\n")

#Used to flag is an element o a tuple should be redacted
def redact(x):
	return -(x+1)



phonetic_alphabet = ['alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel',
'indigo','juliet','kilo','lima','mike','november''oscar','papa','quebec',
'romeo','sierra','tango','uniform','victor','whisky','xray','yankee','zulu']

#Log messages in these classed are internal and OK to keep as they are
passthrough_groups = ["REPL_HB","CONNPOOL","RECOVERY","REPL","STORAGE","JOURNAL","CONTROL","FTDC","ASIO","TRACKING"]

#Regex to Match a log line
timestamp_pattern = r"([0-9T:\+\.\-]{28})"
level_pattern = r"([IEWD])"
logarea_pattern = r"(REPL_HB,CONNPOOL|COMMAND|TRACKING|NETWORK|REPL|ACCESS|WRITE|QUERY|ASIO|FTDC|CONTROL|INDEX|JOURNAL|STORAGE|RECOVERY|SHARDING|-)"
connection_no_pattern  = r"\[(.*?)\]"
optype_pattern = r"([a-zA-Z_\-:\*]*)"
rest_of_line_pattern = r"(.*)$"

pattern = "^%s +%s +%s +%s +%s *%s" % (timestamp_pattern,level_pattern,
									logarea_pattern,connection_no_pattern,
									 optype_pattern,rest_of_line_pattern)

linere = re.compile(pattern)

#How well we are doing
unknown_format_count = 0
match_count = 0



# Define the lines we are happy to output and their redaction
#This code doesnt remote but rather parses and constructs.

#Special cases 

UNCHANGED = (r"^(.*)","%s")
REDACTALL = (r"^(.*)$","%s",(redact(0),))


matcher_cache = {}
#Format is array of Regex to match line, Output, Array of matches to use in output
#With negative number meaning redact, function redact negates number
approved_outputs = {

"NETWORK_end" : (r"^connection(.*)\(([0-9]*) connections? now open\)",
				  "connection %s (%s connections now open))",
				  (redact(0),1)),

"NETWORK_connection" : (r"^accepted from(.*)\(([0-9]*) connections? now open\)",
						 "accepted from %s (%s connections now open)",
						 (redact(0),1)),
"NETWORK_SocketException" : UNCHANGED,
"NETWORK_waiting" : UNCHANGED,
"NETWORK_removing" : UNCHANGED,
"NETWORK_creating" : UNCHANGED,
"NETWORK_Starting" : UNCHANGED,
"NETWORK_connected" : UNCHANGED,
"NETWORK_Started" : UNCHANGED,
"NETWORK_addr" : UNCHANGED,
"NETWORK_listen" : UNCHANGED,
"ACCESS_Unauthorized" : (r"^(not authorized on) (.*?) (to execute command)(.*)$", 
							"%s %s %s %s",(0,redact(1),2,redact(3))),

"NETWORK_closing" : UNCHANGED,
#This one we keep the IP adresses as they are internal cluster IPs
"NETWORK_Failed" : UNCHANGED,
"NETWORK_shutdown:" : UNCHANGED,
"NETWORK_Successfully" : UNCHANGED,
"NETWORK_Refreshing" : UNCHANGED,
"NETWORK_fd" : UNCHANGED,
"NETWORK_DBClientCursor::init":UNCHANGED,
"NETWORK_received" : (r"^(client metadata from) (.*) query: (conn.*)",
						 "%s %s query: %s",(0,redact(1),2)),
"WRITE_remove" : (r"^(.*?) +query: +(.*)(ndeleted.*)$",
					 "%s query: %s %s", (redact(0),redact(1),2)),
"WRITE_warning:" : REDACTALL,
"WRITE_update" : (r"^(.*?) +query: (.*?) update: (.*?) (nscanned.*|keysExamined.*)$",
					 "%s query: %s update: %s %s",(redact(0),redact(1),redact(2),3)),
#TODO - Doesnt get inserts to use collection as already redacted
"WRITE_insert" : (r"^(.*?) +(.*?)(ninserted.*)$",
					 "%s %s %s",(redact(0),redact(1),2)),

"COMMAND_getmore" : (r"^(.*?) +query: (.*)(cursorid.*)$",
					 "%s query: %s %s",(redact(0),redact(1),2)),

"COMMAND_command" : (r"^(.*?) +(command: .*?) (.*?)(planSummary.*|keyUpdates.*|\$clusterTime.*|lsid:.*|numYields.*)$",
					 "%s %s %s %s",
					 (redact(0),1,redact(2),3)),

"COMMAND_query" : (r"^(.*?) +(.*) +(planSummary.*)$",
					 "%s  %s %s",(redact(0),redact(1),2)),

"COMMAND_dropDatabase" : (r"^(.*?) +(.*)$",
					 "%s %s",(redact(0),1)),
"COMMAND_warning:" : (r"^(.*)$","%s",(redact(0),)),
"COMMAND_successfully" : UNCHANGED,
"COMMAND_BackgroundJob" : UNCHANGED,
"COMMAND_shutdown:" : UNCHANGED,
"COMMAND_terminating" : UNCHANGED,
"COMMAND_PeriodicTaskRunner" : UNCHANGED,
"COMMAND_task:" : UNCHANGED,
"COMMAND_killcursors:" : UNCHANGED,
"COMMAND_CMD:" : (r"(.*?) +(.*)$","%s %s",(0,redact(1))),
"QUERY_killcursors" : UNCHANGED,

"QUERY_getmore" : (r"^(.*?) +(.*)(cursorid.*)$",
					 "%s %s %s",(redact(0),redact(1),2)),

"QUERY_query" : (r"^(.*?) +(.*)(planSummary.*)$",
					 "%s %s %s",(redact(0),redact(1),2)),
"QUERY_warning:" : REDACTALL,
"QUERY_Shard" : (r"^request for shard shard : (.*)$",
					 "request for shard shard : %s",(redact(0),)),
#Index build always leaks field name so we only show a bit
"INDEX_build" : (r"^index +(.*?) +(.*?)(scanned.*)?",
				  "index %s %s %s",(0,redact(1),2)),
"INDEX_deleted:" : UNCHANGED,
#building index
"INDEX_" : UNCHANGED,
"INDEX_ns:" : (r"^(.*?) key: (.*)",
				  "%s key: %s",(redact(0),redact(1))),
"ACCESS_Successfully" : (r"^authenticated as principal (.*) on (.*)",
						  "authenticated as principal %s on %s",(redact(0),redact(1))),
"ACCESS_note:": UNCHANGED,
"ACCESS_SCRAM-SHA-":REDACTALL,

"SHARDING_mongos" : UNCHANGED,
"SHARDING_Created" : UNCHANGED,
"-_User" : UNCHANGED,
"-_Creating" : UNCHANGED,
"-_caught" : UNCHANGED
}

#After some thought on the best approach - convert any strings by converting to a 
#low cardinality hash and then using the to lookup a substitution table
#This does let you see if a particular word fits, but also 1000s of other workds work 
#too so is not quite the leakage of a real hash
linesplit = re.compile(r'([\W]+)')
issplitter = re.compile(r'^\W')

def obfuscate(instring):
	#Punctuation and spaces stay as they are
	#number and character sequences get changed
	rval = ""
	parts = linesplit.split(instring)
	operator = False
	for p in parts:
		if issplitter.match(p) or p=="":
			rval=rval+p
			if p.endswith("$"):
				operator=True
			else:
				operator = False
		else:
			try:
				p = int(p) #Exception if not a number
				#Hashing an integer returns itself so cast it
				#But keep 1 and 0 as is
				if p == 1 or p == 0:
					rval = rval + str(p)
				else:
					p = hash(str(p)+"a")%99
					rval = rval + str(p)
			except Exception as e:
				#Short strings starting with $ that are not numbers are shown!
				#On balance they are operators lie $gt or $indexOf
				if operator == True and len(p)<9:
					rval=rval+p
				else:
					hv = hash(p) % (len(phonetic_alphabet)-1)
					rval=rval+phonetic_alphabet[hv]
			operator = False

	return rval


def clean_string(groups,processor):
	newgroups = []
	for groupno in processor:
		if groupno >= 0:
			newgroups.append(groups[groupno])
		else:
			newgroups.append(obfuscate(groups[-(groupno+1)]))
	return newgroups



def process_detail(groups,line_processor):
	global matcher_cache
	match_pattern = line_processor[0]
	redact_template = line_processor[1]
	try:
		match_re = matcher_cache[match_pattern]
	except Exception as e:
		match_re = re.compile(match_pattern)
		matcher_cache[match_pattern] = match_re

	captures = match_re.match(groups[5])
	if captures == None:
		#We just obfuscate the lot!
		return process_detail(groups,REDACTALL)
	else:
		groups = captures.groups()
		if len(line_processor) > 2:
			groups = clean_string(groups,line_processor[2])

		try:
			return redact_template % tuple(groups)
		except Exception as e:
			eprint("ERROR: " + e)
			eprint(groups)
			eprint(redact_template)
			eprint(match_pattern)


def process_logline(groups):
	#print(groups)
	logarea = groups[2]
	optype = groups[4]
	line_processor = approved_outputs.get(logarea+"_"+optype,None)
	if line_processor == None:
		#We do not have a way to process this op
		log_unredacted("NO LOGLINE PROCESSOR: "+ "_".join(groups))
		return None
	else:
		try:
			return process_detail(groups,line_processor)
		except Exception as e:
			eprint(e)
			eprint(groups)
			sys.exit(1)


if __name__ == '__main__':
	if len(sys.argv) != 2:
		eprint ("Usage: python logredact.py <logfile>")
		sys.exit(1)

	#Logfile for writing out lines we can't redact
	unredacted_log =  open("unredacted_lines.log",'w')

	for logline in open(sys.argv[1],'r'):
		o = linere.match(logline)
		if o:
				groups = o.groups()
				#Internal events known to have no user data
				if  groups[2] in passthrough_groups:
					match_count += 1
					print(" ".join(groups[:3])+" ["+groups[3]+"] "+groups[4]+ " "+groups[5])
				else:
					redacted = process_logline(groups)
					if redacted:
						match_count += 1
						print(" ".join(groups[:3])+" ["+groups[3]+"] "+groups[4]+ " "+redacted)
					else:
						unknown_format_count += 1
		else:
				#Do NOT print any lines we can't positively identify
				log_unredacted("UNKNOWN LOGLINE FORMAT: %s" % logline)
				unknown_format_count += 1


	eprint("Censored %d lines. Failed to redact %d lines (wrote to unredacted.log)\n" % (match_count,unknown_format_count) )