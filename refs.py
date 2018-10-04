"""Python Script for analyzing a ReFS - Partition 
Author: 		Henry Georges
Created:		12.08.2017
Last Mod.:	    24.10.2017

This module contains some functions of the sleuthkit, compareable to istat and icat.

Error-Codes:


New Features:	1.1 - Visualization of Dir-Structure
				1.2 - Html-output, Recycle.bin
				1.3 - Flags
				1.4 - Extents
"""
version="1.4 from 24.10.2017"

#__________________________________________________________
#Import needed modules/packages
import struct
import datetime
import time
import sys
import argparse
import os
import platform
from operator import itemgetter, attrgetter, methodcaller
#__________________________________________________________

#__________________________________________________________
"""Simple Function for cleaning the screen in the beginning """
def clearscreen():
    platformOS=platform.system()
    if platformOS == "Windows":
        os.system("cls")
    else:
        os.system("clear")
#__________________________________________________________

#__________________________________________________________
""" checking the existence of files and folders """
def check_file(_filename,opt):
    test="0"
    while test != "1":
        if os.path.isfile(_filename):
            test="1"
            return _filename
        elif os.path.isdir(_filename):
        	test="1"
        	return _filename
        else:
            if opt == 0:
                _filename=raw_input("# Please enter a valid filename with it's absolute path: ")
            elif opt == 1:
                _filename=raw_input("# Please enter a path: ")
                

#__________________________________________________________


#__________________________________________________________
def mbrPartitiontype(_type):
    """determines the partitiontype from the offset 450, 466, 482, 498 from the MBR, at the moment, NTFS/exFAT, und FAT32 are supported
    """
    if _type == 11:
        return "Win95 FAT32"
    elif _type == 7:
        return "NTFS / exFAT"
    elif _type == 0:
        return "empty"
    else:
        print "no"
#__________________________________________________________

#__________________________________________________________
def mbrParser(_filename, _offset):
    """extracts the hexvalues for the partitiontype, the start sector and the length of each partition, the hex-values were converted.. The function returns a tuple: description/start_offset/length
    """
        
    f=open(_filename, "rh")
    f.seek(_offset)
    partition_type=struct.unpack_from("b", f.read(1))[0]
    types=mbrPartitiontype(partition_type)
    f.seek(_offset+4)
    start=struct.unpack_from("<I", f.read(4))[0]
    f.seek(_offset+8)
    length=struct.unpack_from("<I", f.read(4))[0]
    return (types,start, length)
    f.close()
#__________________________________________________________

#__________________________________________________________
def mbrUnallocated(_table, _size):
    """the function calculates the unallocated spaces from the differences in start_offset and end_offset of each partition. The results are returned in a new dictionary, consisting of tuples: description/start_offset/length
    """
    _newtable={}
    m=0
    for k in _table.keys():
        if k == 0:
            _newtable[m]=('Primary Table', 0, 1)
            m=m+1
            if _table[k][1] != 0:
                _newtable[m]=('Unallocated', 0, (int(_table[k][1])-1))
                m=m+1
                _newtable[m]=_table[k]
                m=m+1
            else:
                _newtable[m]=_table[k]
                m=m+1
            
        elif not k == (len(_table.keys())-1):
            if int(_table[k][1]) != (int(_table[k-1][1])+int(_table[k-1][2])):
                _newtable[m]=('Unallocated',(int(_table[k-1][1])+int(_table[k-1][2])),(int(_table[k][1])-(int(_table[k-1][1])+int(_table[k-1][2]))))
                m=m+1
                _newtable[m]=_table[k]
                m=m+1
            else:
                _newtable[m]=_table[k]
                m=m+1
                
        else:
            if _table[k][1] != (int(_table[k-1][1])+int(_table[k-1][2])):
                _newtable[m]=('Unallocated',(int(_table[k-1][1])+int(_table[k-1][2])),(int(_table[k][1])-(int(_table[k-1][1])+int(_table[k-1][2]))))
                m=m+1
                _newtable[m]=_table[k]
                m=m+1
                if int(_table[k][1])+int(_table[k][2]) != int(_size/512):
                    _newtable[m]=('Unallocated',(int(_table[k][1])+int(_table[k][2])), (int(_size/512)- 1 - (int(_table[k][1])+int(_table[k][2])-1)))
            else:
                _newtable[m]=_table[k]
                m=m+1
                if int(_table[k][1])+int(_table[k][2]) == int(_size/512):
                    _newtable[m]=('Unallocated',(int(_table[k][1])+int(_table[k][2])), (int(_size/512) - 1 -(int(_table[k][1])+int(_table[k][2])-1)))

    return _newtable    
#__________________________________________________________

#__________________________________________________________
def analyze_vbr(_filename,offset_partition):
	"""  Analyzes the VolumeBootRecord """
	vbr=[]
	list=()
	f=open(_filename, "rh")
#applying the breakdown-table for the VBR	
	f.seek(int(offset_partition)+3)
	FileSystemName=struct.unpack_from("Q", f.read(8))[0]
#checking, if Fs is a ReFS, oherwise end
	if str(FileSystemName) == "1397122386":
		FileSystemName="ReFS"
	else:
		print_log("FileSystem is not ReFS")
		exit(0)
	f.seek(offset_partition+20)
	bytes_vbr=struct.unpack_from("H", f.read(2))[0]
#reading the checksum from the VBR
	check=struct.unpack_from("H", f.read(2))[0]
#calculating the checkum, using the code delivered by Microsoft, adapted to python
	f.seek(offset_partition)
	calc_check=f.read(64)
	list=struct.unpack_from("B"*64, calc_check)
	count=0
	checksum=0
	for i in list:
		if count == 22 or count == 23:
			count+=1
			continue
		if (checksum & 1) == 1:
			checksum=0x8000+int(checksum>>1)+i
			count+=1
		else:
			checksum=0+int(checksum>>1)+i
			count+=1
#comparing the checksums
	if check == checksum:
		verified=True
	else:
		verified=False
	f.seek(offset_partition+24)
	backupvbr=struct.unpack_from("Q", f.read(8))[0]
	f.seek(offset_partition+32)
	bytespersector=struct.unpack_from("I", f.read(4))[0]
	sectorpercluster=struct.unpack_from("I", f.read(4))[0]
	MajorVersion=struct.unpack_from("B", f.read(1))[0]
	MinorVersion=struct.unpack_from("B", f.read(1))[0]
	f.seek(offset_partition+56)
	volume_id=struct.unpack_from("Q", f.read(8))[0]
	vbr={'Backup VBR':backupvbr,'Volume ID':hex(volume_id),'Verified':verified,'Checksum in VBR':hex(check),'Calculated Checksum':hex(checksum),'Bytes per Sector':bytespersector,'Bytes per Vbr':bytes_vbr,'File System':FileSystemName,'Major Version':MajorVersion,'Minor Version':MinorVersion,'Sectors per Cluster':sectorpercluster,}
	f.close()
	return vbr
#__________________________________________________________

#__________________________________________________________
def creating_output_vbr(vbr,parsed_nodes,free_space_lrg,free_space_med,free_space_sml,dir_structure,partition_size,vbr_offset_partition):
	"""Creating the output for the VBR-Function """
   	report.write("<hr /><h2>Filesystem Information (Fsstat)")
   	
   	print "#"
   	print "# Filesystem Information"
   	report.write("<hr /><h4>Filesystem Information (Offset "+str(vbr_offset_partition)+")</h4><hr /><p> \n")
   	print "#__________________________________________________"
   	print "#"
   	print_table_start()
   	print_log_table("File System Type",vbr['File System'])
   	print_log_table("Filesystem Version",str(vbr['Major Version']) + "." + str(vbr['Minor Version']))
   	print_log_table("Volume ID",vbr['Volume ID'][:-1])
   	print_log_table("Volume Label",parsed_nodes['Node 0x500']['Volume Label'])
   	print_log_table("Checksum in VBR",vbr['Checksum in VBR'])
   	print_log_table("Calculated Checksum",vbr['Calculated Checksum'])
   	if vbr['Verified']:
   		print_log_table("Checksum Verified","True")
   	else:
   		print_log_table("Checksum Verified","False")
   	print "#"
   	print "#"
   	report.write("</small></table></p> \n")
   	report.write("<hr /><h4>Filesystem Layout (in clusters)</h4><hr /><p> \n")
   	print "# File System Layout (in clusters)"
   	print "#__________________________________________________"
   	print_table_start()
   	print_log_table("Total Range (Sectors)",partition_size)
   	print_log_table("Total Range (Bytes)",partition_size*512)
   	print_log_table("Allocated Range (Sectors)",vbr['Backup VBR'])
   	print_log_table("Allocated Range (Bytes)",vbr['Backup VBR']*512)
   	print_log_table("Total Range (GiB)",float(partition_size*512)/1024/1024/1024)
   	print_log_table("Free Space (Bytes)", free_space_lrg+free_space_med+free_space_sml)
   	print_log_table("Free Space (GiB)",(float(free_space_lrg)+free_space_med+free_space_sml)/1024/1024/1024)
   	print_log_table("Free Space (\\%)", (free_space_lrg+free_space_med+free_space_sml)/float(partition_size*512)*100)
   	print_log_table("Volume Boot Record","Sector 0")
   	print_log_table("Backup VBR (Cluster)",vbr['Backup VBR']+vbr_offset_partition-1)
   	print_log_table("Root Node","0x1E")
   	print_log_table("Backup Root Node",vbr['Backup VBR']+vbr_offset_partition-96)
   	print_log_table("Root Directory",parsed_nodes['Node 0x600']['Node: 1']['Dir Label'])
   	report.write("</small></table></p> \n")
   	print "#"
   	print "#"
   	report.write("<hr /><h4>MetaData Information</h4><hr /><p> \n")
   	print "# MetaData Information"
   	print "#__________________________________________________"
   	print_table_start()
   	print_log_table("Created",parsed_nodes['Node 0x500']['Created'])
   	print_log_table("Modified",parsed_nodes['Node 0x500']['Accessed'])
   	report.write("</small></table></p> \n ")
   	print "#"
   	print "#"
   	print "# Content Information"
   	report.write("<hr /><h4>Content Information</h4><hr /><p> \n")
   	print "#__________________________________________________"
   	print_table_start()
   	print_log_table("Sector Size (Bytes)",vbr['Bytes per Sector'])
   	print_log_table("Cluster Size (Sectors)",vbr['Sectors per Cluster'])
   	report.write("</small></table></p> \n")
   	print "#"
   	print "#"

#__________________________________________________________

#__________________________________________________________
def mbrMain_function(filename):
	"""Analyzes the Masterbootrecord """

#getting the size of the file
	size = os.stat(filename).st_size

#determining the kind of partitiontable
	offset=450
    
#look up for the values of the 4 possible partitions in mbr, the mbr-function is called and the offsets for checking are handed over
	i=0
	table={}
	while i != 4:
		table[i]=mbrParser(filename, offset)
		i=i+1
		offset=offset+16

#in case of empty values, the table is cleaned up, the sortedtable is a dictionary consisting of touples (no empty ones) 
	sortedtable={}
	for k in table.keys():
		if table[k][0] != "empty":
			sortedtable[k]=table[k]

#the unallocated-function is called and the sortedtable and the size of the image are handed to it. The function returns a newtable, including also the unallocated space.
	newtable={}
	newtable=mbrUnallocated(sortedtable, size)


#the output is created, so that it looks similiar to the mmls output, using the format-command
#some basic informations to the partitiontype:
	report.write("<hr /><h2>Partition-Table Analysis (mmls)</h2><p> \n ")
	print "# "
	print_log("DOS Partition Table")
	print_log("Offset Sector: 0")
	print_log("Units are in 512-bytes sectors</p> \n ")
	print "# "

#head of the partitiontable
	print_table_start()
	print_log_table_mmls("","Start","End","Length","Description",0)
	

#the content of the newtable is edited, so that is similiar to the mmls-output, and printed on the the screen
	for k in newtable.keys():
		print_log_table_mmls(k,newtable[k][1],(int(newtable[k][1]) + int(newtable[k][2])),newtable[k][2],newtable[k][0],1)
	report.write("</small></table></p> \n")
	return newtable
	

#__________________________________________________________


#__________________________________________________________
"""Checking, if amount of pointers equals amount of records """
def check_pointers_records(_pointer,_record,_node):
	if _pointer != _record:
		print "Mismatch pointers to records in Node " + hex(_node) +"; Rec: " + str(_record) +"; Point: "+ str(_pointer)
#__________________________________________________________

#__________________________________________________________	
"""Parsing the $Tree_Control, returning the single offsets for the Entry-Blocks """	
def tree_control(_offset_part,_number_tree):
	offset_object_tree=_offset_part + _number_tree*16384
	f.seek(offset_object_tree+88)
	amount_record=struct.unpack_from("I", f.read(4))[0]
	offset_record=struct.unpack_from("I", f.read(4))[0]
	f.seek(offset_object_tree+offset_record)
	i=0
	node=[]
	for i in range(amount_record):
		offset_entry_block=struct.unpack_from("H", f.read(2))[0]
		node.append(offset_entry_block)
		f.read(22)
		i+=1
	return node
#__________________________________________________________

#__________________________________________________________
"""Getting the Length of the Node-Descriptor and the amount of records """
def node_descriptor(_offset):
	f.seek(_offset+48)
	length=struct.unpack_from("H", f.read(2))[0]
	f.seek(_offset+80)
	amount=struct.unpack_from("H", f.read(2))[0]
	return length,amount
#__________________________________________________________

#__________________________________________________________
"""Getting the pointers from a node, by looking up the offset to pointers and the amount of pointers in the Node-Header """
def node_pointers(_offset,_amount_records,_node):
	f.seek(_offset +16)
	first_pointer=struct.unpack_from("I", f.read(4))[0]
	amount=struct.unpack_from("I", f.read(4))[0]
	if _amount_records != -1:
		check_pointers_records(amount,_amount_records,_node)
	f.seek(_offset+first_pointer)
	j=0
	pointers=[]
	for j in range(amount):
		offset_record=struct.unpack_from("I", f.read(4))[0]
		pointers.append(offset_record)
		j+=1
	return pointers
#__________________________________________________________

#__________________________________________________________
"""Parsing the single nodes of the $Tree_Control """
def tree_control_nodes(_offset_part,_node):
	offset_node=_offset_part+_node*16384
	(length_node_descriptor,amount_records)=node_descriptor(offset_node)
	pointers=node_pointers(offset_node+48+length_node_descriptor,amount_records,_node)

	return pointers,length_node_descriptor
#__________________________________________________________	

#__________________________________________________________
"""Parsing the $Object, returning the Node ID's, Cluster Offsets for each record """
def object_record_parser(_offset,pointers):
	k=0
	j=0
	for k in pointers:
		start_record=_offset+pointers[j]
		f.seek(start_record+24)
		node_id=struct.unpack_from("I", f.read(4))[0]
		f.seek(start_record+32)
		cluster_offset=struct.unpack_from("I", f.read(4))[0]
		f.seek(start_record+72)
		unknown_value=struct.unpack_from("I", f.read(4))[0]
		object_record={'Record No':j,'Node ID':hex(node_id),'Cluster Offset':cluster_offset,'Unknown':unknown_value}
		object_records.append(object_record)
		j+=1
	return object_records
#__________________________________________________________

#__________________________________________________________
"""Function for returning, if a byte is set (needed for allocation) """
def testBit(integer,offset):
	mask=1 << offset
	return (integer & mask)
#__________________________________________________________

#__________________________________________________________
"""Parsing the allocation table for finding free bytes """
def calc_free_space(length,last_byte,table):
	free=0
	for n in range(length):
			for o in range(last_byte):
				vars=testBit(table[n],o)
				if vars == 0:
					free+=1	
	return free
#__________________________________________________________

#__________________________________________________________
"""Parsing the EntryBlocks containing the Allocator_Lrg,_Med,_Sml,returning the amount of unallocated EntryBlocks """
def allocator_parser(_offset,pointers,blocks_per_bit,max_bytes):
	k=0
	j=0
	free_cluster=0
	for k in pointers:
		table=[]
		start_record=_offset+pointers[j]
		f.seek(start_record+16)
		starting_block=struct.unpack_from("Q", f.read(8))[0]
		amount_blocks=struct.unpack_from("Q", f.read(8))[0]
		f.seek(start_record+64)
		offset_start_table=struct.unpack_from("I", f.read(4))[0]
		length_table=struct.unpack_from("I", f.read(4))[0]
		for m in range(length_table):
			var=struct.unpack_from("B", f.read(1))[0]
			table.append(var)
		real_length_table=amount_blocks/blocks_per_bit/8
		if real_length_table != max_bytes:
			free_cluster+=calc_free_space(real_length_table,8,table)
			free_cluster+=calc_free_space(1,amount_blocks/blocks_per_bit%8,table)
		else:	
			free_cluster+=calc_free_space(len(table),8,table)
		allocator_record={'Record No':j,'Allocation Table':table,'Starting Block':starting_block,'Amount Blocks':amount_blocks,'Offset Start Table':offset_start_table,'Length Table':length_table}
		allocator_records.append(allocator_record)
		j+=1
	free_space=free_cluster*blocks_per_bit*16384	
	return free_space
#__________________________________________________________

#__________________________________________________________
"""Parsing the $Object to get the directory-structure"""
def directory_structure(_offset,pointers):
		dir_structure=[]
		j=0
		
		for k in pointers:
			f.seek(_offset+k+24)
			node_id=struct.unpack_from("I", f.read(4))[0]
			f.seek(_offset+k+40)
			child_id=struct.unpack_from("I", f.read(4))[0]
			if len(dir_structure) == 0:
				j+=1
				node_name="Node"+str(j)
				node={}
				node[node_name]=node_id
				node["Child"]=[]
				if child_id != 0:
					node["Child"].append(child_id)
				dir_structure.append(node)
			else:
				control=0
				for i in range(len(dir_structure)):
					node_name="Node"+str(i)
					cache=dir_structure[i]
					if node_id in cache.values():
						cache["Child"].append(child_id)
						control+=1
				if control == 0:
					j+=1
					node_name="Node"+str(j)
					node={}
					node[node_name]=node_id
					node["Child"]=[]
					if child_id != 0:
						node["Child"].append(child_id)
					dir_structure.append(node)
		return dir_structure
#__________________________________________________________

#__________________________________________________________
"""Converting Windows Filetime into human readable format """
def getFiletime(dt):
	time=dt/10000000
	d=datetime.datetime.strptime("01-01-1601", "%m-%d-%Y")
	return (d+datetime.timedelta(seconds= int(time))).strftime("%a, %d %b %Y %H:%M:%S UTC")
#__________________________________________________________

#__________________________________________________________
"""Parsing the System Node (Node 0x500), returning the Volume Label, Created and Accessed Timestamps and the offset to UpCase Table """
def node_500_parser(_offset):
	node_500={}
	(length_node_descriptor,amount_records)=node_descriptor(_offset)
	pointers=node_pointers(_offset+48+length_node_descriptor,-1,0)
	for j in pointers:
		offset_record=_offset+48+length_node_descriptor+j
		f.seek(offset_record+16)
		counter_node_id=struct.unpack_from("I", f.read(4))[0]
		if hex(counter_node_id) == "0x510":
			f.seek(offset_record+10)
			start_name=struct.unpack_from("H", f.read(2))[0]
			length_name=struct.unpack_from("H", f.read(2))[0]
			f.seek(offset_record+start_name)
			label_volume=struct.unpack("B"*length_name, f.read(length_name))
			volume_label=""
			i=0
			for k in label_volume:
				if not i%2:
					volume_label+=chr(k)
				i+=1
			node_500['Volume Label']=volume_label
		if hex(counter_node_id) == "0x520":
			f.seek(offset_record+168)
			node_500['Created']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
			f.seek(offset_record+184)
			node_500['Accessed']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
		if hex(counter_node_id) == "0x530":
			f.seek(offset_record+224)
			node_500['Upcase Table']=struct.unpack_from("I",f.read(4))[0]
	return node_500		
#__________________________________________________________

#__________________________________________________________
"""Function for parsing the header of files and folders """ 
def record_header_file_folder(_offset):
	f.seek(_offset)
	record_length=struct.unpack_from("I",f.read(4))[0]
	record_header_length=struct.unpack_from("H",f.read(2))[0]
	offset_end_first_structure=struct.unpack_from("H",f.read(2))[0]
	f.read(2)
	next_structure=struct.unpack_from("H",f.read(2))[0]
	f.read(4)
	return record_length,record_header_length,offset_end_first_structure,next_structure	
#__________________________________________________________

#__________________________________________________________	
"""Function for parsing nodes """
def node_parser(_offset):
	node={}							#dictionary for the node 0x600
	#_offset=offset+k['Cluster Offset']*16384 #calling the cluster offsets from the object_records
#Parsing the Node descriptor and the Node Header, returning  the length of the Descriptor, the offsets for the pointers and other values
	(length_node_descriptor,amount_records)=node_descriptor(_offset)
	pointers=node_pointers(_offset+48+length_node_descriptor,-1,0)
#Parsing the records, according to the pointers
	for j in range(len(pointers)):
		nodes={}					#dictionary for the single records
		count=len(node)+1
		offset_record=_offset+48+length_node_descriptor+pointers[j]
		f.seek(offset_record+16)
		attribute_identifier=struct.unpack_from(">I",f.read(4))[0]
#Parsing the 0x10000000 attribute, the parent Directory, in case of Node 0x600 the $Root
		if hex(attribute_identifier) == "0x10000000":
			f.seek(_offset+48+length_node_descriptor+pointers[j])
			record_length=struct.unpack_from("I",f.read(4))[0]
			f.read(2)
			record_inside_amount=struct.unpack_from("H",f.read(2))[0]
			f.read(2)
			record_header_length=struct.unpack_from("H",f.read(2))[0]
			inside_offset=_offset+48+length_node_descriptor+pointers[j]+24
#Parsing the records inside the first record						
			for m in range(record_inside_amount):
				f.seek(inside_offset)
				record_inside_length=struct.unpack_from("I",f.read(4))[0]
#Parsing the timestamps
				if m == 0:	
					offset_to_timestamp=struct.unpack_from("H",f.read(2))[0]
					f.seek(inside_offset+offset_to_timestamp)
					nodes['Created']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
					nodes['Modified']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
					nodes['Metadata Modified']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
					nodes['Last Accessed']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
					f.read(8)
					int_node_id=struct.unpack_from("I",f.read(4))[0]	
				if m == 1:
					pass
				if m == 2:
					pass
				if m == 3:
#parsing the Name
					if hex(int_node_id) == "0x600":
						f.seek(inside_offset+16)
						pointer_to_name_end=struct.unpack_from("H",f.read(2))[0]
						f.seek(inside_offset+ 24)
						length_name=struct.unpack_from("H",f.read(2))[0]
						pointer_to_name_start=pointer_to_name_end - length_name
						f.seek(inside_offset + 16+pointer_to_name_start)
						name=struct.unpack_from("B"*length_name, f.read(length_name))
						dir_label=""
						i=0
						for k in name:
							if not i%2:
								dir_label+=chr(k)
							i+=1
						nodes['Dir Label']=dir_label
						nodes['Node Typ: ']="Root Directory"
						nodes['Attribute']=attribute_identifier
						nodes['Node ID']=int_node_id
						node['Node: '+str(count)]=nodes
						
					elif hex(int_node_id) == "0x520":
						f.seek(inside_offset+16)
						offset_end_name=(struct.unpack_from("I",f.read(4))[0])+32
						length_name=offset_end_name-132
						f.seek(inside_offset+126)
						name=struct.unpack_from("B"*length_name, f.read(length_name))
						dir_label=""
						i=0
						for k in name:
							if not i%2:
								dir_label+=chr(k)
							i+=1
						nodes['Dir Label']=dir_label
						nodes['Node Typ: ']="Folder"
						nodes['Attribute']=attribute_identifier
						nodes['Node ID']=int_node_id
						node['Node: '+str(count)]=nodes
						
					#elif hex(int_node_id) == "0x701" or hex(int_node_id) == "0x702":
					else:
						f.seek(inside_offset+60)
						nodes['Alternate Timestamp 1']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
						nodes['Alternate Timestamp 2']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
						nodes['Alternate Timestamp 3']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
						nodes['Alternate Timestamp 4']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
						f.seek(inside_offset+16)
						offset_end_name=(struct.unpack_from("I",f.read(4))[0])+32
						length_name=offset_end_name-132	
						f.seek(inside_offset+126)
						name=struct.unpack_from("B"*length_name, f.read(length_name))
						dir_label=""
						i=0
						for k in name:
							if not i%2:
								dir_label+=chr(k)
							i+=1
						nodes['Dir Label']=dir_label
						nodes['Node Typ: ']="Folder"
						nodes['Attribute']=attribute_identifier
						nodes['Node ID']=int_node_id
						node['Node: '+str(count)]=nodes
				inside_offset+=record_inside_length
#Parsing the FNA
		if hex(attribute_identifier) == "0x30000200" or hex(attribute_identifier) == "0x30000100":
			(record_length,record_header_length,offset_end_first_structure,second_structure)=record_header_file_folder(_offset+48+length_node_descriptor+pointers[j])
			f.seek(_offset+48+length_node_descriptor+pointers[j]+record_header_length+4)
			name=struct.unpack_from("B"*(offset_end_first_structure-4), f.read(offset_end_first_structure-4))
			structure_name=""
			if hex(attribute_identifier) == "0x30000200":
				folder_name=""
				i=0
				for k in name:
					if not i%2:
						folder_name+=chr(k)
					i+=1
				f.seek(_offset+48+length_node_descriptor+pointers[j]+second_structure)
				int_node_id=struct.unpack_from("H",f.read(2))[0]
				f.read(14)
				nodes['Folder Name']=folder_name
				nodes['Created']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
				nodes['Modified']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
				nodes['Metadata Modified']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
				nodes['Last Accessed']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
				nodes['Node Typ: ']="Folder"
				nodes['Attribute']=attribute_identifier
				nodes['Node ID']=int_node_id
				node['Node: '+str(count)]=nodes
#Distinguishing Files from Folders							
			if hex(attribute_identifier) == "0x30000100":
				
				file_name=""
				i=0
				for k in name:
					if not i%2:
						file_name+=chr(k)
					i+=1
				f.seek(_offset+48+length_node_descriptor+pointers[j]+second_structure)
				meta_data_record_length=struct.unpack_from("I",f.read(4))[0]
				meta_data_offset_timestamp=struct.unpack_from("H",f.read(2))[0]
				f.seek(_offset+48+length_node_descriptor+pointers[j]+second_structure+meta_data_offset_timestamp)
				nodes['Attribute']=attribute_identifier
				nodes['File Name']=file_name
				nodes['Created']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
				nodes['Modified']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
				nodes['Metadata Modified']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
				nodes['Last Accessed']=getFiletime(struct.unpack_from("Q",f.read(8))[0])
				nodes['Flags']=struct.unpack_from("B",f.read(1))[0]
				f.read(7)
				int_node_id=struct.unpack_from("H",f.read(2))[0]
				f.read(6)
				nodes['Child ID']=struct.unpack_from("I",f.read(4))[0]
				nodes['Node Typ: ']="File"
#Getting the logical and physical Filesize							
				f.seek(_offset+48+length_node_descriptor+pointers[j]+second_structure+meta_data_offset_timestamp+32+32)
				nodes['Logical Filesize']=struct.unpack_from("Q",f.read(8))[0]
				nodes['Physical Filesize']=struct.unpack_from("Q",f.read(8))[0]
				nodes['Node ID']=int_node_id
#Datarun-Attribute, contains two records, the second contains the Dataruns
				f.seek(_offset+48+length_node_descriptor+pointers[j]+second_structure+meta_data_record_length)
				data_run_record_header_length=struct.unpack_from("I",f.read(4))[0]
				f.seek(_offset+48+length_node_descriptor+pointers[j]+second_structure+meta_data_record_length+data_run_record_header_length)
				first_datarun_record_length=struct.unpack_from("I",f.read(4))[0]
				f.read(6)
				first_datarun_record_header_length=struct.unpack_from("H",f.read(2))[0]
				offset_first_datarun=_offset+48+length_node_descriptor+pointers[j]+second_structure+meta_data_record_length+data_run_record_header_length+first_datarun_record_header_length
				f.seek(offset_first_datarun)
				data_run_first_subrecord_length=struct.unpack_from("I",f.read(4))[0]
				f.seek(offset_first_datarun+data_run_first_subrecord_length)
				second_datarun_header_length=struct.unpack_from("I",f.read(4))[0]
#Parsing the Dataruns
				f.read(12)
				second_datarun_offset_pointers=node_pointers(offset_first_datarun+data_run_first_subrecord_length,-1,0)
				z=1
				datarun=[]
				for x in second_datarun_offset_pointers:
					offset_data_run=offset_first_datarun+data_run_first_subrecord_length+x
					f.seek(offset_data_run)
					length_data_run=struct.unpack_from("I",f.read(4))[0]
					f.read(20)
					amount_clusters=struct.unpack_from("Q",f.read(8))[0]
					start_cluster=struct.unpack_from("Q",f.read(8))[0]
					run={}
					run['DataRun']=z
					run['Amount Clusters']=amount_clusters
					run['Size Run']=amount_clusters*16384
					run['Start Cluster']=start_cluster
					datarun.append(run)
					z+=1
				nodes['DataRun']=datarun
				node['Node: '+str(count)]=nodes
#Parsing the records containing childs
		if hex(attribute_identifier) == "0x20000080":
			f.seek(_offset+48+length_node_descriptor+pointers[j]+24)
			parent_id=struct.unpack_from("I",f.read(4))[0]
			f.seek(_offset+48+length_node_descriptor+pointers[j]+32)
			file_id=struct.unpack_from("H",f.read(2))[0]
			f.seek(_offset+48+length_node_descriptor+pointers[j]+48)
			file_name_true=struct.unpack_from("H",f.read(2))[0]
			file_name=""
			if hex(file_name_true) == "0xc":
				length_file_name=struct.unpack_from("H",f.read(2))[0]
				name=struct.unpack_from("B"*length_file_name,f.read(length_file_name))
				#file_name=""
				i=0
				for k in name:
					if not i%2:
						file_name+=chr(k)
					i+=1
				nodes['File Name']=file_name
			nodes['Parent ID']=parent_id
			nodes['File ID']=file_id
			nodes['Attribute']=attribute_identifier
			nodes['Node Typ: ']="Child"
			node['Node'+str(count)]=nodes
	return node
#____________________________________

#____________________________________
""" Function for parsing the $Tree_control """
def tree_structure(_filename,_offset,_newtable):
	global parsed_nodes
	offset=_offset*512
	f=open(_filename, 'rh')
	f.seek(offset)
	vbr=struct.unpack_from("Q", f.read(8))[0]
	for j in range(len(_newtable)):
		if _offset == _newtable[j][1]:
			partition_size=_newtable[j][2]
	offset_root_node=offset+30*16384
	f.seek(offset_root_node)
	f.read(160)
# Looking up the amount of records within the $Tree_control
	number_object_tree=struct.unpack_from("H", f.read(2))[0]
#Looking up the Node_ID and the Cluster-Offset for each record within the $Tree_Control
	records_tree_control=tree_control(offset,number_object_tree)
	pointers={}
	i=0
#Calling the single entries of the records_tree_control for further examination
	for i in range(len(records_tree_control)):
#Looking up the pointers and the length of the nodedescriptor
		(pointers,length_node_descriptor)=tree_control_nodes(offset, records_tree_control[i])
# $Object_Tree
		if i == 0:
#Parsing the $Object_Tree, returning the Node_ID, the Cluster-Offset and an unknown value
			object_records=object_record_parser(offset+records_tree_control[i]*16384+48+length_node_descriptor,pointers)
			for k in object_records:
				f.seek(offset+k['Cluster Offset']*16384+24)
				node_id=struct.unpack_from("I", f.read(4))[0]
#Parsing the Node_ID 0x500 - $System
				if hex(node_id) == "0x500":
					parsed_nodes['Node '+str(hex(node_id))]=node_500_parser(offset+k['Cluster Offset']*16384)
				
#Parsing the Node_ID 0x600 - Root-Directory
				else:
					f.seek(offset+k['Cluster Offset']*16384+72)
					test_extent=struct.unpack_from("B",f.read(1))[0]
					if test_extent == 0 :
						parsed_nodes['Node '+str(hex(node_id))]=node_parser(offset+k['Cluster Offset']*16384)
						
					else:
						parsed_nodes=node_extents(offset, offset+k['Cluster Offset']*16384, node_id, parsed_nodes)
					
		if i == 1:
			free_space_lrg=allocator_parser(offset+records_tree_control[i]*16384+48+length_node_descriptor,pointers,4096,32)
		if i == 2:
			free_space_med=allocator_parser(offset+records_tree_control[i]*16384+48+length_node_descriptor,pointers,4,128)
		if i == 3:
			free_space_sml=allocator_parser(offset+records_tree_control[i]*16384+48+length_node_descriptor,pointers,1,128)
		if i == 5:
			dir_structure=directory_structure(offset+records_tree_control[i]*16384+48+length_node_descriptor,pointers)
						
	f.close()
	return partition_size,parsed_nodes,free_space_lrg,free_space_med,free_space_sml,dir_structure
#__________________________________________________________

#__________________________________________________________
def node_extents(offset,_offset,node_id, parsed_nodes):
	f.seek(_offset+72)
	extent=struct.unpack_from("B", f.read(1))[0]
	pointers=node_pointers(_offset+280,-1,0)
	pointer_extent=[]
	for i in range(len(pointers)):
		f.seek(_offset+280+pointers[i]+10)
		offset_to_extent=struct.unpack_from("B", f.read(1))[0]
		f.seek(_offset+280+pointers[i]+offset_to_extent)
		extents_offset=struct.unpack_from("I", f.read(4))[0]
		pointer_extent.append(extents_offset)
	_parsed_nodes={}
	nodes={}
	count=0
	for i in range(len(pointer_extent)):
		_parsed_nodes=node_parser(offset+(pointer_extent[i]*16384))
		for k,v in _parsed_nodes.items():
			count+=1
			nodes['Node: ' +str(count)]=v
	parsed_nodes['Node '+str(hex(node_id))]=nodes
	
	return parsed_nodes
	
#__________________________________________________________	


#__________________________________________________________
"""Function for searching nodes with the searchparameter field"""
def search_key(nodes,field):
	global mylist
	for key,value in nodes.items():
		extract_node={}
		try:
			if field in nodes[key]:
				try:
					if nodes[key]["File Name"][0] != "$":
						extract_node={}
						extract_node["Struct ID"]='.'.join([str(nodes[key]["Parent ID"]),str(nodes[key]["File ID"])])
						extract_node["File ID"]=nodes[key]["File ID"]
						extract_node["Parent ID"]=nodes[key]["Parent ID"]
						extract_node["File Name"]=nodes[key]["File Name"]
						mylist.append(extract_node)
				except KeyError:
					pass
		except AttributeError and TypeError:
			pass
		if type(value) == dict:
			search_key(value,field)
	return mylist
#__________________________________________________________

#__________________________________________________________
"""Function for searching nodes with the searchparameter field in the $Recycling.bin """
def search_key_recycle(nodes):
	global mylist_recycle
	print "Inside Sort Recycle"
	for key in range(len(nodes)):
		extract_node={}
		try:
			try:
				extract_node={}
				extract_node["Struct ID"]='.'.join([str(nodes[key]["Recycle Node ID"]),str(nodes[key]["Recycle Child ID"])])
				extract_node["File ID"]=nodes[key]["Recycle Child ID"]
				extract_node["Parent ID"]=nodes[key]["Recycle Node ID"]
				extract_node["File Name"]=nodes[key]["Old Filename"]
				mylist_recycle.append(extract_node)
			except KeyError:
				pass
		except AttributeError and TypeError:
			pass
	return mylist_recycle
#__________________________________________________________

#__________________________________________________________
"""Function for recursive structure analysis, creating the output in command line"""
def dir_structure_subnode(objects,field,lines):
	for k in range(len(objects)):
		if field == objects[k]["Node"+str(k+1)]:
			lines+=str(" "*7)+ "| "
			for k1 in range(len(objects[k]["Child"])):
				print lines
				for k2 in parsed_nodes["Node "+str(hex(objects[k]["Child"][k1]))].keys():
					if "Dir Label" in parsed_nodes["Node "+str(hex(objects[k]["Child"][k1]))][k2]:
						#report.write(lines_l+str("-"*3)+"> Node " +str(hex(objects[k]["Child"][k1]))+" (" + parsed_nodes["Node "+str(hex(objects[k]["Child"][k1]))][k2]["Dir Label"] + ") <br> \n")
						print lines+str("-"*3)+"> Node " +str(hex(objects[k]["Child"][k1]))+ " (" + parsed_nodes["Node "+str(hex(objects[k]["Child"][k1 ]))][k2]["Dir Label"] + ")"
				dir_structure_subnode(objects,objects[k]["Child"][k1],lines)
#__________________________________________________________

#__________________________________________________________
"""Function for recursive structure analysis, creating the output in html"""
def dir_structure_subnode_l(objects,field,lines_l):
	global report
	for k in range(len(objects)):
		if field == objects[k]["Node"+str(k+1)]:
			lines_l+=str("&nbsp; "*7)+ "| "
			for k1 in range(len(objects[k]["Child"])):
				report.write(lines_l+"<br> \n")
				for k2 in parsed_nodes["Node "+str(hex(objects[k]["Child"][k1]))].keys():
					if "Dir Label" in parsed_nodes["Node "+str(hex(objects[k]["Child"][k1]))][k2]:
						report.write(lines_l+str("-"*3)+"> Node " +str(hex(objects[k]["Child"][k1]))+" (" + parsed_nodes["Node "+str(hex(objects[k]["Child"][k1]))][k2]["Dir Label"] + ") <br> \n")
						#print lines+str("-"*3)+"> Node " +str(hex(objects[k]["Child"][k1]))+ " (" + parsed_nodes["Node "+str(hex(objects[k]["Child"][k1 ]))][k2]["Dir Label"] + ")"
				
				#report.write(lines_l+str("-"*3)+"> Node " +str(hex(objects[k]["Child"][k1]))+" (" + parsed_nodes["Node "+str(hex(objects[k]["Child"][k1]))]["Node: 1"]["Dir Label"] + ") <br> \n")
				dir_structure_subnode(objects,objects[k]["Child"][k1],lines_l)	
#__________________________________________________________

#__________________________________________________________
"""Function for structure analysis, calling the recursive dir_structure_subnode-function"""
def dir_structure_output(objects,parsed_nodes):
	global report
	lines=str("# ")+ "| "
	print "#"
	print "#################################################"
	print "# Analyzing the directory structure"
	print "#"
	for k in range(len(objects)):
		if hex(objects[k]["Node"+str(k+1)]) == "0x600":
			print "# Node " + str(hex(objects[k]["Node"+str(k+1)]))+ " (" +parsed_nodes["Node "+str(hex(objects[k]["Node"+str(k+1)]))]["Node: 1"]["Dir Label"] + ")"
			for l in range(len(objects[k]["Child"])):
				print lines
				for k2 in parsed_nodes["Node "+str(hex(objects[k]["Child"][l]))].keys():
					if "Dir Label" in parsed_nodes["Node "+str(hex(objects[k]["Child"][l]))][k2]:
						#report.write(lines_l+str("-"*3)+"> Node " +str(hex(objects[k]["Child"][k1]))+" (" + parsed_nodes["Node "+str(hex(objects[k]["Child"][k1]))][k2]["Dir Label"] + ") <br> \n")
						print lines+str("-"*3)+"> Node " +str(hex(objects[k]["Child"][l]))+ " (" + parsed_nodes["Node "+str(hex(objects[k]["Child"][l]))][k2]["Dir Label"] + ")"
				
				
				#print lines+str("-"*3)+"> Node " +str(hex(objects[k]["Child"][l]))+ " (" + parsed_nodes["Node "+str(hex(objects[k]["Child"][l]))]["Node: 1"]["Dir Label"] + ")"
				dir_structure_subnode(objects,objects[k]["Child"][l],lines)
			print "#"
	report.write("<hr /><h2>Directory Structure Analyse</h2>")
	lines_html=str("&nbsp;")+ "| "
	for k in range(len(objects)):
		if hex(objects[k]["Node"+str(k+1)]) == "0x600":
			report.write("Node " + str(hex(objects[k]["Node"+str(k+1)]))+" (" + 
				parsed_nodes["Node "+str(hex(objects[k]["Node"+str(k+1)]))]["Node: 1"]["Dir Label"] + ")""<br> \n")
			for l in range(len(objects[k]["Child"])):
				report.write(lines_html+"<br> \n")
				for k2 in parsed_nodes["Node "+str(hex(objects[k]["Child"][l]))].keys():
					if "Dir Label" in parsed_nodes["Node "+str(hex(objects[k]["Child"][l]))][k2]:
						report.write(lines_l+str("-"*3)+"> Node " +str(hex(objects[k]["Child"][l]))+" (" + parsed_nodes["Node "+str(hex(objects[k]["Child"][l]))][k2]["Dir Label"] + ") <br> \n")
						#print lines+str("-"*3)+"> Node " +str(hex(objects[k]["Child"][k1]))+ " (" + parsed_nodes["Node "+str(hex(objects[k]["Child"][k1 ]))][k2]["Dir Label"] + ")"
				
				
				#report.write(lines_html+str("-"*3)+"> Node " +str(hex(objects[k]["Child"][l]))+" (" + 
				#parsed_nodes["Node "+str(hex(objects[k]["Child"][l]))]["Node: 1"]["Dir Label"] + ") <br> \n")
				dir_structure_subnode_l(objects,objects[k]["Child"][l],lines_html)
			
#__________________________________________________________

#__________________________________________________________
"""Function for validating, if Offset to partition is given"""
def get_offset():
	global vbr_offset_partition
	try:
		print "# Offset to partition:  ",vbr_offset_partition,"\n"
	except NameError:
			print ""
			offset_int_loop=int(raw_input("# Please enter the offset to the partition : "))
			vbr_offset_partition=offset_int_loop
	return vbr_offset_partition
#__________________________________________________________

#__________________________________________________________
"""Function for extracting the File-Information from the single nodes, recursive part,
creating also the output to the print_log_table-function"""
def get_file_details(nodes,search):
	global file_details
	global report
	field="Child ID"
	for key,value in nodes.items():
		try:
			if field in nodes[key]:
				if nodes[key][field] == int(search):
					file_details=nodes[key]
					print_table_start()
					print "#"
					print "############################################"
					print "# Details for File"
					print_log_table("Filename",nodes[key]["File Name"])
					print_log_table("Parent ID",hex(nodes[key]["Node ID"]))
					print_log_table("Created",nodes[key]["Created"])
					print_log_table("Modified",nodes[key]["Modified"])
					print_log_table("Metadata Modified",nodes[key]["Metadata Modified"])
					print_log_table("Last Accessed",nodes[key]["Last Accessed"])
					try:
						if bin(nodes[key]["Flags"])[-1] == "1":
						 	print_log_table("Read - Only Flag: ","X")
						if bin(nodes[key]["Flags"])[-2] == "1":
						 	print_log_table("Hidden Flag: ","X")
						if bin(nodes[key]["Flags"])[-6] == "1":
						 	print_log_table("Archive Flag: ","X")
					except IndexError:
						pass
					print_log_table("Logical Filesize",nodes[key]["Logical Filesize"])
					print_log_table("Physical Filesize",nodes[key]["Physical Filesize"])
					print_log_table("Extents/Fragments",len(nodes[key]["DataRun"]))
					report.write("</small></table>")
					report.write("<table style=\"border-collapse; border: 1px solid black; border radius: 5px;text-align: justify; margin-left:150px\"><small>")
					for data in nodes[key]["DataRun"]:
						print_log_table("Data Run",data["DataRun"])
						print_log_table(" "*40+"Start Cluster",data["Start Cluster"])
						print_log_table(" "*38+"Amount Clusters",data["Amount Clusters"])
						print_log_table(" "*40+"Size Data Run",data["Size Run"])
					report.write("</small></table>")	
		except AttributeError and TypeError:
			pass
		if type(value) == dict:
			get_file_details(value,search)	
#__________________________________________________________


def get_file_details_recycle(nodes,search):
	global file_details_recycle
	global report
	field="Recycle Child ID"
	if nodes[field] == int(search) :
		file_details_recycle=nodes
		print_table_start()
		print "#"
		print "############################################"
		print "# Details for deleted File"
		print_log_table("Recycled Filename",nodes["Filename"])
		print_log_table("Recycled Node ID",nodes["Recycle Node ID"])
		print_log_table("Recycled Child ID",nodes["Recycle Child ID"])
		print_log_table("Original Filename",nodes["Old Filename"])
		print_log_table("Cluster Offset old filename",nodes["Offset old Filename"])
		print_log_table("Original Logical Filesize", nodes["Logical Filesize"])
		print_log_table("Original Node ID",nodes["Former Node ID"])
		print_log_table("Original Child ID",nodes["Former Child ID"])
		print_log_table("Originaly Created",nodes["Originaly Created"])
		print_log_table("Deleted",nodes["Deleted"])
		for data in nodes["DataRun"]:
			print_log_table("Data Run",data["DataRun"])
			print_log_table(" "*40+"Start Cluster",data["Start Cluster"])
			print_log_table(" "*38+"Amount Clusters",data["Amount Clusters"])
			print_log_table(" "*40+"Size Data Run",data["Size Run"])
		report.write("</small></table>")		
#__________________________________________________________  
"""Function for extracting the File-Information from the single nodes, calling the recursive get_file_details-function"""  
def get_file_details_node(nodes,search):
	split_node,split_file=search.split(".")
	if type(nodes) == dict:
		for key,value in nodes.items():
			try:
				if key == str("Node "+hex(int(split_node))):
					get_file_details(value,split_file)
			except AttributeError and TypeError:
				pass
	elif type(nodes) == list:
		for key in range(len(nodes)):
			get_file_details_recycle(nodes[key],split_file)			
#__________________________________________________________

#__________________________________________________________
def get_node_num(nodes):
	global extract
	global node_num
	for keys,values in nodes.items():
		try:
			if "Dir Label" in nodes[keys]:
				if nodes[keys]["Dir Label"] == "$RECYCLE.BIN":
					node_num=nodes[keys]["Node ID"]
		except TypeError:
			pass
		if type(values) == dict :
			get_node_num(values)
#__________________________________________________________

#__________________________________________________________
def get_nodes(nodes,field):
	global extract
	del_nodes=[]
	for keys,values in nodes[field].items():
		if hex(nodes[field][keys]["Attribute"]) == "0x30000200":
			del_nodes.append(nodes[field][keys]["Node ID"])
	return del_nodes
#__________________________________________________________

#__________________________________________________________
def get_recyclebin(del_nodes,parsed_nodes):
	for k in range(len(del_nodes)):
		for l in parsed_nodes["Node "+str(hex(del_nodes[k]))].keys():
			del_file={}
			if hex(parsed_nodes["Node "+str(hex(del_nodes[k]))][l]["Attribute"]) == "0x30000100":
				if parsed_nodes["Node "+str(hex(del_nodes[k]))][l]["File Name"][:2] == "$I":
					new_filename=parsed_nodes["Node "+str(hex(del_nodes[k]))][l]["File Name"]
					new_short_filename=new_filename[-(len(new_filename)-2):]
					for k_r in range(len(del_nodes)):
						for l_r in parsed_nodes["Node "+str(hex(del_nodes[k_r]))].keys():
							if hex(parsed_nodes["Node "+str(hex(del_nodes[k_r]))][l_r]["Attribute"]) == "0x30000100":
								if parsed_nodes["Node "+str(hex(del_nodes[k_r]))][l_r]["File Name"][:2] == "$R":
									new_filename_r=parsed_nodes["Node "+str(hex(del_nodes[k_r]))][l_r]["File Name"]
									new_short_filename_r=new_filename_r[-(len(new_filename_r)-2):]
									if new_short_filename == new_short_filename_r:
										del_file["Filename"]=new_short_filename_r
										del_file["Recycle Node ID"]=parsed_nodes["Node "+str(hex(del_nodes[k]))][l]["Node ID"]
										del_file["Recycle Child ID"]=parsed_nodes["Node "+str(hex(del_nodes[k]))][l]["Child ID"]
										del_file["Deleted"]=parsed_nodes["Node "+str(hex(del_nodes[k]))][l]["Created"]
										del_file["Offset old Filename"]=parsed_nodes["Node "+str(hex(del_nodes[k]))][l]["DataRun"][0]["Start Cluster"]
										offset_old_filename=(vbr_offset_partition + int(parsed_nodes["Node "+str(hex(del_nodes[k]))][l]["DataRun"][0]["Start Cluster"])*32)*512
										f=open(filename, "rh")
										f.seek(offset_old_filename+32)
										del_file["Size Filename"]=parsed_nodes["Node "+str(hex(del_nodes[k]))][l]["Logical Filesize"]-32
										size_filename_old= parsed_nodes["Node "+str(hex(del_nodes[k]))][l]["Logical Filesize"] -32
										old_filename=struct.unpack_from("B"*size_filename_old, f.read(size_filename_old))
										filename_old=""
										i=0
										for k in old_filename:
											if not i%2:
												filename_old+=chr(k)
											i+=1
										f.close()
										del_file["Old Filename"]=filename_old										
										del_file["Former Node ID"]=parsed_nodes["Node "+str(hex(del_nodes[k_r]))][l_r]["Node ID"]
										del_file["Former Child ID"]=parsed_nodes["Node "+str(hex(del_nodes[k_r]))][l_r]["Child ID"]
										del_file["Originaly Created"]=parsed_nodes["Node "+str(hex(del_nodes[k_r]))][l_r]["Modified"]
										del_file["Logical Filesize"]=parsed_nodes["Node "+str(hex(del_nodes[k_r]))][l_r]["Logical Filesize"]
										del_file["DataRun"]=parsed_nodes["Node "+str(hex(del_nodes[k_r]))][l_r]["DataRun"]
										recyclebin_node.append(del_file)
	return recyclebin_node
#__________________________________________________________





#__________________________________________________________
#########################################################################################
#                                                                                       #
#                                  Report                                               #
#                                                                                       #
#########################################################################################

#__________________________________________________________
""" Calling some information to the case and examiner, writing the html-header"""
def report_function(report_switch):
    global report
    global time
    time=time.strftime("%d.%m.%Y %H:%M:%S")
    global officer_name
    if report_switch == "1":
        officer_name=raw_input("Please enter your name: ")
        case_number=raw_input("Please enter the case number: ")
        evidence_number=raw_input("Please enter the evidence number: ")
        report_file=raw_input("Please enter the path for the report: ")
        report_filename=""
        while not os.path.isdir(report_file) or os.path.isfile(report_filename):
            print "Path is not valid or file already existent."
            report_file=raw_input("Please enter a valid/empty path for the report: ")
            report_filename=report_file + "/report.tex"
        report_filename=report_file + "/report.html"
    	report=open(report_filename,"a")
        report.write("<!DOCTYPE html> \n <html> \n <head> \n <TITLE>Case: ReFS</TITLE> \n </head> \n <body>"
        				"<h1><center>ReFS - Analysis</center></h1><hr /> \n "
        				)
        report.write("<hr /><h2>Case Information</h2><p>")
        print_table_start()
        report.write("<tr><td>Examiner's Name: </td><td>"+str(officer_name)+"</td></tr> \n")
        report.write("<tr><td>Case number: </td><td>"+str(case_number)+"</td></tr> \n")
        report.write("<tr><td>Evidence Number: </td><td>"+str(evidence_number)+"</td></tr> \n")
        report.write("<tr><td>Starting time of examination: </td><td>"+str(time)+"</td></tr> \n")
        report.write("</small></table></p>")
        return report_filename,report_file
    else:
        if len(officer_name) == 0:
        	report_file="/tmp"
        	report_filename=report_file + "/report.html"
        	officer_name=""
        	return report_filename,report_file
#__________________________________________________________

#__________________________________________________________
""" writing the html-footer"""
def report_function_end():
    global report
    report.write("</body> \n </html>")
    report.close()
#__________________________________________________________

#__________________________________________________________
"""Simple function for piping a string to the commandline and to a html-file"""    
def print_log(string):
    global report
    print "# ",string
    report.write(string+" <br> \n ")
#__________________________________________________________

#__________________________________________________________
"""Simple function for piping two values into an html-table and to the cli,
table with two columns"""
def print_log_table(key,value):
    global report
    report.write("<tr><td>"+key+":</td><td>"+str(value)+"</td></tr> \n")
    print "# {:>35} : {:<60}".format(key,value)
#__________________________________________________________

#__________________________________________________________
"""Simple function for piping five values into an html-table and to the cli,
table with five columns"""
def print_log_table_mmls(value1,value2,value3,value4,value5,header):
    global report
    if header == 0:
    	print "{:<2}{:>3}{:2}{:<10}{:2}{:<10}{:2}{:<10}{:2}{:<20}".format("# ",value1,"",value2,"",value3,"",value4,"",value5)
    	report.write("<tr><td width=30>"+value1+"</td><td width=120>"+value2+"</td><td width=120>"+value3+"</td><td width=120>"+value4+"</td><td>"+value5+"</td></tr> \n ")
    else:
    	print "{:<2}{:>03d}{:2}{:>010d}{:2}{:>010d}{:2}{:>010d}{:2}{:<20}".format("# ",value1,"",value2,"",value3,"",value4,"",value5)
    	report.write("<tr><td>"+str(value1)+"</td><td>"+str(value2)+"</td><td>"+str(value3)+
    					"</td><td>"+str(value4)+"</td><td>"+str(value5)+"</td></tr> \n ")
#__________________________________________________________

#__________________________________________________________
"""Simple function for piping four values into an html-table and to the cli,
table with four columns"""
def print_log_table_files(value1,value2,value3,value4):
	global report
	print "# {:<20} | {:<20} | {:<20} | {:<60}".format(value1,value2,value3,value4)
	report.write("<tr><td>"+str(value1)+"</td><td>"+str(value2)+"</td><td>"+str(value3)+"</td><td>"+str(value4)+"</td></tr> \n ")
#__________________________________________________________

#__________________________________________________________
"""Creating the standard table code for html"""
def print_table_start():
	global report
	report.write("<table style=\"border-collapse; border: 1px solid black; border radius: 5px\"><small>")
#__________________________________________________________

#__________________________________________________________
#########################################################################################
#                                                                                       #
#                                   Main-Menu                                           #
#                                                                                       #
#########################################################################################

def mainMenu():
    print "#################################################"
    print "# Tool for analyzing ReFS-Partitions and extracting files from ReFS"
    print "#"
    print "# Menu"
    print "#"
    print "# r/R  Enable the Report Function"
    print "#"
    print "# 1. Analyzing the MBR (mmls))"
    print "# 2. Analyzing the Volume Information (fsstat)"
    print "# 3. Analyzing the directory structure"
    print "# 4. List the current files (fls)"
    print "# 5. Files (istat/icat)"
    print "# 6. $Recycle.bin"
    print "#"
    print "# q/Q for Quit"
    print "#"
    choiceMainMenu=raw_input("Please enter your choice: ")
    print "#"
    print "#"
    return choiceMainMenu
#__________________________________________________________  



#__________________________________________________________
#########################################################################################
#                                                                                       #
#                                  Main - Function                                      #
#                                                                                       #
#########################################################################################

#__________________________________________________________
"""Defining some globel variables """
global filename,extract_path
filename=""
global mylist, mylist_recycle
global file_details
global report
global officer_name
officer_name=""
report=open("/tmp/report.tex","w")
object_records=[]
allocator_records=[]
parsed_nodes={}
#__________________________________________________________


clearscreen()

choiceMainMenu=mainMenu()
while choiceMainMenu.lower() != "q" :
    report_switch=""
    if choiceMainMenu == "1":
        print "################################################"
        print "# Analyzing the MBR"
        print "#"
        #filename=raw_input("# Please enter the path to the image: ")
        filename=check_file(filename,0)
        
        newtable=mbrMain_function(filename)
        print "#"
        print "#"
    elif choiceMainMenu == "2":
    	print "################################################"
    	print "# FileSystem"
    	print "#"
        filename=check_file(filename,0)
        f=open(filename,'rh')
        vbr_offset_partition_1=raw_input("# Please enter the offset to the partition (q/Q for Quit): ")
        if vbr_offset_partition_1.lower() != "q":
        	vbr_offset_partition=int(vbr_offset_partition_1)
        	vbr=analyze_vbr(filename,(int(vbr_offset_partition)*512))
        	partition_size,parsed_nodes,free_space_lrg,free_space_med,free_space_sml,dir_structure=tree_structure(filename,vbr_offset_partition,newtable)
        	creating_output_vbr(vbr,parsed_nodes,free_space_lrg,free_space_med,free_space_sml,dir_structure,partition_size,vbr_offset_partition)
        	f.close()
        else:
        	pass
    elif choiceMainMenu == "3":
    	print "################################################"
        print "# Directory Structure"
        print "#"
    	filename=check_file(filename,0)
    	try:
        	print "# Offset to partition:  ",vbr_offset_partition,"\n"
        	dir_structure_output(dir_structure,parsed_nodes)
        except NameError:
			print "#\n"
			print "# Please choose option 2 first"
			print "#"
    	
    elif choiceMainMenu == "4":
    	print "################################################"
        print "# List Files"
        report.write("<hr /><h2>List current Files</h2>")
        print "#"
        filename=check_file(filename,0)
        try:
        	print_log(" Offset to partition:  "+str(vbr_offset_partition))
        	mylist=[]
        	child_list=[]
        	child_list=sorted(search_key(parsed_nodes,"File ID"),key=lambda k: k['Struct ID'])
        	print "#"
        	print "#################################################"
        	print "# Current Files:"
        	print "#"
        	print_table_start()
        	print_log_table_files("Internal ID","File ID","Parent ID","File Name")
        	print "#----------------------|----------------------|----------------------|--------------------------------------------------"
        
        	for k in range(len(child_list)):
        		#print_log_table_files(child_list[k]["Struct ID"],child_list[k]["File ID"],hex(child_list[k]["Parent ID"]),"\\_".join(child_list[k]["File Name"].split("_")))
        		try:
        			print_log_table_files(child_list[k]["Struct ID"],child_list[k]["File ID"],hex(child_list[k]["Parent ID"]),child_list[k]["File Name"])  
        		except KeyError:
        			pass
        	print "#"
        	report.write("</small></table></p>")
        except NameError:
			print "#\n"
			print "# Please choose option 2 first"
			print "#"
    elif choiceMainMenu == "5":
    	print "################################################"
        report.write("<hr /><h2>File Details</h2>")
        print "# File Details:"
        print "#"
        filename=check_file(filename,0)
        vbr_offset_partition=get_offset()
        try:
        	if child_list:
        		pass
        except NameError:
        	print "# Please execute 3 first"
        which_file=raw_input("Please enter the Internal ID you want details for: ")
        report.write("<p>Details for File: "+str(which_file)+" </p><br> \n" )
        file_details={}
        get_file_details_node(parsed_nodes,which_file)
        choice=raw_input("Do you want to extract the file ? (y/n): ")
        if choice.lower() != "n":
        	print "#"
        	print "#################################################"
        	print "#Extract"
        	print "#"
        	extract_path=raw_input("Please enter the path for extracting the file: ")
        	extract_path=check_file(extract_path,1)
        	f=open(filename,"r")
        	cumulated_filesize=0
        	for key in range(len(file_details["DataRun"])):
        		extract_filename=extract_path+"/"+file_details["File Name"]
        		g=open(extract_filename,"a")
        		f.seek((int(file_details["DataRun"][key]["Start Cluster"])*16384)+(int(vbr_offset_partition)*512))
        		
        		if (file_details["Logical Filesize"]-cumulated_filesize-file_details["DataRun"][key]["Size Run"]) >= 0:
        			run=file_details["DataRun"][key]["Amount Clusters"]*16384
        			cumulated_filesize+=file_details["DataRun"][key]["Size Run"]
        		else:
        			full_clusters=(file_details["Logical Filesize"]-cumulated_filesize)//16384
        			rest_cluster=file_details["Logical Filesize"]%16384
        			run=rest_cluster+(full_clusters*16384)
        		
        		g.write(f.read(run))
        	f.close()
        	g.close()
        	print_log("\n The file with ID " + str(which_file) + " was copied to " + extract_path)
        else:
        	pass 
    
    elif choiceMainMenu == "6":
    	
		global extract
		global node_num
		extract={}
		get_node_num(parsed_nodes)
		del_nodes=get_nodes(parsed_nodes,"Node "+hex(node_num))
		recyclebin_node=[]
		recyclebin_node=get_recyclebin(del_nodes,parsed_nodes)
		mylist_recycle=[]
		child_list_recycle=[]
		child_list_recycle=sorted(search_key_recycle(recyclebin_node),key=lambda k: k['Struct ID'])
		print "#"
		print "#################################################"
		print "# Deleted Files:"
		print "#"
		report.write("<hr /><h2>List deleted Files</h2>")
		print_table_start()
		print_log_table_files("Internal ID","File ID","Parent ID","File Name")
		print "#----------------------|----------------------|----------------------|--------------------------------------------------"
		for k in range(len(child_list_recycle)):
			try:
				print_log_table_files(child_list_recycle[k]["Struct ID"],child_list_recycle[k]["File ID"],hex(child_list_recycle[k]["Parent ID"]),child_list_recycle[k]["File Name"])
			except KeyError:
				pass
		print "#"
		report.write("</small></table></p>")
		which_file=raw_input("Please enter the Internal ID you want details for: ")
		file_details_recycle={}
		if which_file.lower() != "q":
			report.write("<p>Details for deleted File: "+str(which_file)+" </p><br> \n" )
			get_file_details_node(recyclebin_node,which_file)
		choice=raw_input("Do you want to extract the file ? (y/n): ")
		if choice.lower() != "n":
			print "#"
			print "#################################################"
			print "#Extract"
			print "#"
			extract_path=raw_input("Please enter the path for extracting the file: ")
			extract_path=check_file(extract_path,1)
			f=open(filename,"r")
			cumulated_filesize=0
			for key in range(len(file_details_recycle["DataRun"])):
				extract_filename=extract_path+"/"+file_details_recycle["Filename"]
				g=open(extract_filename,"a")
				f.seek((int(file_details_recycle["DataRun"][key]["Start Cluster"])*16384)+(int(vbr_offset_partition)*512))
				if (file_details_recycle["Logical Filesize"]-cumulated_filesize-file_details_recycle["DataRun"][key]["Size Run"]) >= 0:
					run=file_details_recycle["DataRun"][key]["Amount Clusters"]*16384
					cumulated_filesize+=file_details_recycle["DataRun"][key]["Size Run"]
				else:
					full_clusters=(file_details_recycle["Logical Filesize"]-cumulated_filesize)//16384
					rest_cluster=file_details_recycle["Logical Filesize"]%16384
					run=rest_cluster+(full_clusters*16384)
				g.write(f.read(run))
			f.close()
			g.close()
			print_log("\n The file with ID " + str(which_file) + " was copied to " + extract_path)
		else:
			pass 

    
    elif choiceMainMenu == "9":
    	pass
    elif choiceMainMenu.lower() == "r":
		report_switch="1"
		report_filename,report_file=report_function(report_switch)
    else:
        print "invalid choice"
    choiceMainMenu=mainMenu()

try:
	if report_file:
		report_function_end()
except NameError:
	report_file="/tmp/"
	report_filename="/tmp/report.tex"
