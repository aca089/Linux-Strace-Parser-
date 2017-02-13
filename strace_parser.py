import re
import networkx as nx
import matplotlib.pyplot as plt
# matplotlib.use('TkAgg')

#Function that writes common system calls

fname = "gimp_detailed2.txt"
G = nx.Graph()
inputs_array=[]
outputs_array=[]
instructions_array=[]

def common_syscalls():
	f = open('Gimp_screenshot_details','r')
	#Read the line
	line = f.readline()
	common = open("gimp_common_details.txt","w")

	valid_syscalls=["read","poll","munmap","clone","writev","open","recvmsg","lseek","close","brk","lstat","fstat","fcntl","readlink","uname"]
	#Read the file line by line
	while line:
		line = f.readline()
		common_syscall = line.partition("(")[0]
		if (common_syscall in valid_syscalls):
			common.write(line)

	f.close()
	common.close()


#Delete recvmsg commands that outputted resource temporarily unavailable
def recvmsg_edit():

	f_read = open("gimp_common_details.txt","r")
	f_write = open("gimp_detailed2.txt","w+")

	line = f_read.readline()

	while line:
		line =f_read.readline()
		# print "as"
		recvmsg_output = line.partition("=")[2]
		# print recvmsg_output
		# f_write.write(recvmsg_output)
		if ("EAGAIN" not in recvmsg_output):
			f_write.write(line)

	f_read.close()
	f_write.close()

# Make an instruction object with attributes - inputs, output, sequence number, instruction type

############################################################################################################
#Object Declarations
class Instruction_Object:

	def __init__(self,output,sequence_no,instruction_type,inputs =[]):
		self.inputs = inputs
		self.output = output
		self.sequence_no = sequence_no
		self.instruction_type=instruction_type
		return

#Classes for input arguments and outputs of the strace calls
class argument_object:

	def __init__(self,data_type,sequence,arguments=[]):
		self.arguments = arguments
		self.data_type = data_type
		self.sequence = sequence
		return

class output_object:

	def __init__(self,output,sequence,data_type):
		self.output =output
		self.data_type = data_type
		self.sequence=sequence
		return

############################################################################################################



#Extracts output of a line
def extract_output(line):
	#Get arguments on the right of '='
	# print line
	line_partition = re.findall('\s=\s(\w.*)',line)
	if (line_partition):
		line_partition=line_partition[0]
	# print line_partition
	# x =re.findall('fd=(\d*)',line_partition)
	return line_partition


#Gets entire output from extract_output and retains only the relevant output
def process_output(line):
	# print line
	str_out = extract_output(line)
	# print str_out
	if ("fd" in str_out):
		# print "in if statement"
		output =re.findall('fd=(\d*)',str_out)
		output_type = 'fd'
	elif ("0x" in str_out):
		output =re.findall('0x(\w*)',str_out)
		output_type = 'address'
	else:
		output = '0'
		output_type='0'

	# print output	
	return output,output_type

	# print "not in if statement"

############################################################################################################


#Outputs length of file
def file_len(fname):
	# fname = "gimp_detailed2.txt"
	with open(fname) as f:
		for i, l in enumerate(f):
			pass
	return i+1

#Debugging purposes,
def print_output():
	f = open(fname,"r")
	line = f.readline()
	for i in xrange(file_len(fname)):
		line = f.readline()
		line_temp = extract_output(line)
		print line_temp

############################################################################################################

#Extracts Instruction from a line
def extract_instruction(line):
	instruction = line.partition("(")[0]
	return instruction

############################################################################################################

#Extract Argument from a line
#Requirements: 
#line has to be in single quotes
def extract_argument(line):
	argument_array =[]
	input_type='0'
	instruction = extract_instruction(line)
	#If instruction is read
	if (instruction=='read'):
		fd = line.partition("(")[2]
		fd = fd.partition(",")[0]
		# address = 0
		# path = 0
		argument_array.append(fd)
		input_type = 'fd'
		# argument_array.append(address)
		# argument_array.append(path)
	
	# munmap(0x7fccc19ab000, 200704)          = 0
	if (instruction=='munmap'):
		address = line.partition("(")[2]
		address = address.partition(",")[0]
		# argument_array.append(0)
		argument_array.append(address)
		input_type = 'address'
		# argument_array.append(0)


# poll([{fd=4, events=POLLIN}, {fd=3, events=POLLIN}, {fd=5, events=POLLIN}, {fd=10, events=POLLIN|POLLPRI}], 4, 0) = 0 (Timeout)
	if (instruction=='poll'):
		fd = re.findall('fd=(\d*)',line)
		argument_array.append(fd)
		input_type = 'fd'
		#No address
		# argument_array.append(0)
		#No paths or anything
		# argument_array.append(0)
		# print argument_array

#recvmsg(3, {msg_name(0)=NULL, msg_iov(1)=[{"\1\1?[\0\0\0\0\213\22\340\1\310\0\305\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 4096}], msg_controllen=0, msg_flags=0}, 0) = 32
	if (instruction=='recvmsg'):
		fd =re.findall(r'\d{1,20}',line)
		fd = fd[0]
		argument_array.append(fd)
		input_type='fd'
		# argument_array.append(0)
		# argument_array.append(0)
		# print argument_array

	#clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fcce289dc90) = 7399
	if (instruction=='clone'):
		address =re.findall('0x(\w*)',line)[0]
		# argument_array.append(0)
		argument_array.append(address)
		input_type = 'address'
		# argument_array.append(0)
		# print argument_array

	#writev(3, [{"+\0\1\0", 4}, {NULL, 0}, {"", 0}], 3) = 4
	if (instruction=='writev'):
		fd =re.findall(r'\d{1,20}',line)
		fd = fd[0]
		argument_array.append(fd)
		input_type = 'fd'
		# argument_array.append(0)
		# argument_array.append(0)
		# print argument_array

	#open("/usr/lib/gimp/2.0/plug-ins/screenshot", O_RDONLY) = 17
	if (instruction =='open'):
		temp_path = line.partition('(')[2]
		new_path = temp_path.split(",")
		path = new_path[0]
		# argument_array.append(0)
		# argument_array.append(0)
		argument_array.append(path)
		input_type = 'path'
		# print argument_array

	#close(17)                               = 0
	if (instruction =='close'):
		fd =re.findall(r'\d{1,20}',line)
		fd = fd[0]
		argument_array.append(fd)
		input_type = 'fd'
		# argument_array.append(0)
		# argument_array.append(0)
		# print argument_array

	#brk(0x3ac6000)                          = 0x3ac6000
	if(instruction =='brk'):
		address =re.findall('0x(\w*)',line)[0]
		# argument_array.append(0)
		argument_array.append(address)
		input_type='address'
		# argument_array.append(0)
		# print argument_array

	#In fstat, I have not taken into account st_mode. 
	#fstat(14, {st_mode=S_IFIFO|0600, st_size=0, ...}) = 0

	if (instruction=='fstat'):
		fd =re.findall(r'\d{1,20}',line)
		fd = fd[0]
		argument_array.append(fd)
		input_type ='fd'
		# argument_array.append(0)
		# argument_array.append(0)
		# print argument_array

	#I haven't taken into account the WRONLY and RDONLY Flags. Might help to take that into account
	#fcntl(14, F_GETFL)                      = 0x1 (flags O_WRONLY)
	if (instruction=='fcntl'):
		fd =re.findall(r'\d{1,20}',line)
		fd = fd[0]
		argument_array.append(fd)
		input_type='fd'
		# argument_array.append(0)
		# argument_array.append(0)
		# print argument_array

	#Removing nested loops
	if (any(isinstance(i,list) for i in argument_array)==True):
		return argument_array[0],input_type
	else:
		return argument_array,input_type

############################################################################################################


#Make all objects and assign them
def make_objects(fname):
	f = open(fname,'r')
	line = f.readline()
	count = 0
	while line:
		line = f.readline()
		sequence = count
		args,arg_type = extract_argument(line)
		# print args
		out,out_type = process_output(line)
		instr_type = extract_instruction(line)
		instr_obj = Instruction_Object(instruction_type = instr_type,inputs = args, sequence_no= sequence,output= out)
		G.add_node(instr_obj.instruction_type)
		instructions_array.append(instr_obj)
		arg_object = argument_object(data_type=arg_type,sequence=count,arguments=args)
		inputs_array.append(arg_object)
		out_object = output_object(output=out,sequence=count,data_type=out_type)
		outputs_array.append(out_object)
		count = count+1
	f.close()


make_objects(fname)

def make_Edges(instructions_array,inputs_array,outputs_array):
	for inst in instructions_array[:file_len(fname)-10]:
		for j in xrange(10):
			# G.add_node(inst)
			next_inst = instructions_array[inst.sequence_no+j]
			intersection = [val for val in inputs_array[inst.sequence_no].arguments if val in inputs_array[inst.sequence_no+j].arguments]
			# print intersection
			# print "intersection"
			# return
			if (len(intersection)!=0):
				print intersection
				G.add_edge(inst,next_inst)

make_Edges(instructions_array,inputs_array,outputs_array)
# nx.draw(G)
# plt.show()
# plt.savefig('fig.png')


# extract_argument('fcntl(14, F_GETFL)                      = 0x1 (flags O_WRONLY)')
# extract_output('clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fcce289dc90) = 7399')
# process_output('poll([{fd=3, events=POLLIN|POLLOUT}], 1, 4294967295) = 1 ([{fd=3, revents=POLLOUT}])')
# process_output('brk(0x3ac6000)                          = 0x3ac6000')





	