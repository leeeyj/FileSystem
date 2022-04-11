'''
<NTFS Analysis Program> 
Date : 2022.04.01 ~ 
Creater : Yong Jin Lee (from Information Security, Math and Cryptography, Kookmin.Univ, Seoul)
'''

'''
<Data Hiding> 
 1. File Slack 
 2. MFT-Entry Slack 
 3. Unallocation MFT-Entry 
 4. Change allocation MFT-Entry to Unallocation MFT-Entry 
 5. ADS?
'''


from tkinter import filedialog
from collections import deque
import os

class NTFS:
    def __init__(self, fileName):
        # Read NTFS
        self.buffer = open(fileName, 'rb')
        self.image = self.buffer.read()
        self.buffer.close()

        self.type = self.image[0x3:0xB].decode('utf-8')
        self.BootSector = self.image[:512]
        self.sector = int.from_bytes(self.BootSector[0xB:0xD], byteorder='little')                          # byte
        self.cluster = self.BootSector[0xD] * self.sector                                                   # byte 
        self.VBR_Size = self.cluster                                                                        # byte
        self.MFT_Offset = int.from_bytes(self.BootSector[0x30:0x38], byteorder='little') * self.cluster     # byte

        self.MFT, self.MFT_Location = self.__MFT()     # MFT-Area
        self.FileTree, self.MFT_Entry_Address_File = self.__FileTree()
        self.File_MFT_Entry_Address = {v[0]:k for k, v in self.MFT_Entry_Address_File.items()}
        self.FileTreeView =  'Root Directory\n'+ self.__DFS(5, 0)
        # self.File_MFT_Entry_Address = self.__FileTree()


    # Get type of File System
    def getType(self):
        return self.type

    # Get NTFS informations 
    def getNTFSInfo(self):
        return self.sector, self.cluster, self.VBR_Size, self.MFT_Offset

    # Get MFT
    def getMFTInfo(self):
        return self.MFT_Location 

    # Get File Tree in NTFS
    def getFileTree(self):
        return print(self.FileTreeView)

    # Get File informations 
    def getFileInfo(self, FileName):
        return self.__FileInfo(FileName)
    
    # Get Directory informations 
    def getDirInfo(self, DirName):
        return self.__DirInfo(DirName)
    
    # File Analysis 
    def __FileInfo(self, FileName):
        if self.MFT_Entry_Address_File[self.File_MFT_Entry_Address[FileName]][1] != 'File' or \
            self.MFT_Entry_Address_File[self.File_MFT_Entry_Address[FileName]][1] != 'Deleted File':
            return print(FileName + ' is not File')
        
        MFT_Entry = self.MFT[self.File_MFT_Entry_Address[FileName] * 1024:(self.File_MFT_Entry_Address[FileName] + 1) * 1024]

        MFT_Entry_Header = MFT_Entry[:48]
        Sequence_Number, Attr_Offset, Flags, Used_MFT_Entry_Size = self.__MFT_Entry_Header(MFT_Entry_Header)

        MFT_Entry_Attr = MFT_Entry[Attr_Offset:Used_MFT_Entry_Size-4]
        self.__MFT_Entry_Attr(MFT_Entry_Attr)




    # Directory Analysis 
    def __DirInfo(self, DirName):
        if self.MFT_Entry_Address_File[self.File_MFT_Entry_Address[DirName]][1] != 'Directory' or \
            self.MFT_Entry_Address_File[self.File_MFT_Entry_Address[DirName]][1] != 'Deleted Directory':
            return print(DirName + ' is not Directory')
        
        MFT_Entry = self.MFT[self.File_MFT_Entry_Address[DirName] * 1024:(self.File_MFT_Entry_Address[DirName] + 1) * 1024]
        

    def __MFT_Entry_Header(self, MFT_Entry_Header):
        Sequence_Number = int.from_bytes(MFT_Entry_Header[16:18], byteorder='little')
        Attr_Offset = int.from_bytes(MFT_Entry_Header[20:22], byteorder='little')
        Flags = int.from_bytes(MFT_Entry_Header[22:24], byteorder='little')
        Used_MFT_Entry_Size = int.from_bytes(MFT_Entry_Header[24:28], byteorder='little')
        
        return Sequence_Number, Attr_Offset, Flags, Used_MFT_Entry_Size


    def __MFT_Entry_Attr(self, MFT_Entry_Attr):

    def __Resident_Attr(self, Attr):
    
    def __Non_Resident_Attr(self, Attr):





    # Export MFT Area
    def ExportMFT(self):
        f = open('./MFT', 'wb')       
        if self.MFT != None:
            f.write(self.MFT)
            f.close()
            return print('Export Success!!')
        else:
            f.close()
            return print('Export Fail')

    # MFT Area 
    def __MFT(self):
        buffer = self.image[self.MFT_Offset:self.MFT_Offset + 1024]         # $MFT
        buffer = buffer[int.from_bytes(buffer[20:22], byteorder='little'):] # $MFT Attribute part 
        while buffer[:4] != b'\xff\xff\xff\xff':                                # 0xFFFFFFFF = End of Marker 
            if int.from_bytes(buffer[:4], byteorder='little') == 128:       # Finding $Data 
                buffer = buffer[:int.from_bytes(buffer[4:8], byteorder='little')]
                break
            else:
                buffer = buffer[int.from_bytes(buffer[4:8], byteorder='little'):]
        else:
            return None, None 

        RunLength, RunOffset, MFT, MFT_location = 0, 0, b'', [] 
        if buffer[8] == 1:
            buffer = buffer[int.from_bytes(buffer[32:34], byteorder='little'):]  # Run-List location 
            while True:     # Find Run List 
                Byte1 = buffer[0]
                if Byte1 == 0:
                    break
                else:
                    RunLength = int.from_bytes(buffer[1:1+(Byte1 & 15)], byteorder='little') * self.cluster 
                    RunOffset = int.from_bytes(buffer[1+(Byte1 & 15):1+(Byte1 & 15) + (Byte1 >> 4)], byteorder='little') * self.cluster       
                
                MFT += self.image[RunOffset:RunOffset + RunLength]
                MFT_location.append((RunOffset, RunOffset + RunLength - 1))

                if 1 + (Byte1 & 15) + (Byte1 >> 4) == len(buffer):
                    break
                else:
                    buffer = buffer[1 + (Byte1 & 15) + (Byte1 >> 4):]
        else:
            return None, None  
        return MFT, MFT_location

    def __FileTree(self):
        MFT = self.MFT 
        MFT_Entry_Address_File = {} # {MFT-Entry-Address : (File Name, File Type)}
        File_Tree = {} # {root: [Dir1, Dir2, File1, File2, .... ], }
        
        if self.MFT == None:
            return print('File or MFT Area does not exist on NTFS.')
        else:
            MFT_Entry_Address = 0
            while MFT_Entry_Address  < len(MFT) // 1024:
                MFT_Entry = MFT[MFT_Entry_Address * 1024:(MFT_Entry_Address + 1 ) * 1024]           # MFT_Entry 
                
                if MFT_Entry[4:6] == b'\x00\x00':                                                     # Unallocated MFT-Entry
                    MFT_Entry_Address += 1
                    continue
                
                File_Type = int.from_bytes(MFT_Entry[22:24], byteorder='little')                    # File Type(File or Dir)
                if File_Type == 0:  File_Type = 'Deleted File'
                elif File_Type == 1:    File_Type = 'File'
                elif File_Type == 2:    File_Type = 'Deleted Directory'
                elif File_Type == 3:    File_Type = 'Directory'
                else : File_Type = 'Unknown'

                MFT_Entry = MFT_Entry[int.from_bytes(MFT_Entry[20:22], byteorder='little'):]        # MFT_Entry Attribute part
                while MFT_Entry[:4] != b'\xff\xff\xff\xff':                                             # 0xFFFFFFFF = End of Marker 
                    if int.from_bytes(MFT_Entry[:4], byteorder='little') == 48:                     # Finding $File_Name  
                        MFT_Entry = MFT_Entry[:int.from_bytes(MFT_Entry[4:8], byteorder='little')]
                        break
                    else:
                        MFT_Entry = MFT_Entry[int.from_bytes(MFT_Entry[4:8], byteorder='little'):]
                else:
                    MFT_Entry_Address += 1
                    continue

                if MFT_Entry[8] == 0:                                                               # Checking $File_Name Attr Type 
                    MFT_Entry = MFT_Entry[int.from_bytes(MFT_Entry[20:22], byteorder='little'):]    # $File_Name Contents
                    
                    # File_Reference_Address = (Sequence Number, File_Entry_Address)
                    # 부모 디렉터리 주소 = (부모 디렉터리의 Sequence Number, 부모 디렉터리의 File_Entry_Address)
                    # File_Tree 를 만들 때 사용할 것 
                    File_Refer_of_parent_dir = (int.from_bytes(MFT_Entry[6:8], byteorder='little'), int.from_bytes(MFT_Entry[:6], byteorder='little'))
                    
                    File_Name = b''                                 # Get File Name 
                    for i in range(0, MFT_Entry[64] * 2, 2):
                        File_Name += bytes([MFT_Entry[66 + i]])
                    File_Name = File_Name.decode('utf-8')
                
                MFT_Entry_Address_File[MFT_Entry_Address] = (File_Name, File_Type)
                
                # Create File Tree 
                if File_Refer_of_parent_dir[1] not in File_Tree:
                    if MFT_Entry_Address != 5:
                        File_Tree[File_Refer_of_parent_dir[1]] = [MFT_Entry_Address]
                else: 
                    if MFT_Entry_Address != 5:
                        File_Tree[File_Refer_of_parent_dir[1]].append(MFT_Entry_Address)
                
                MFT_Entry_Address += 1

        # return MFT_Entry_Address_File
        return File_Tree, MFT_Entry_Address_File
    

    def __DFS(self, start, depth):
        # <This function must be implemented recursively.>
        stack = deque()
        s = ''
        stack.extend(self.FileTree[start])
        
        while stack:
            node = stack.popleft()
            if node in self.FileTree:
                if depth > 0: s += '  ' * depth + '-> ' + '%s(%s)' %(self.MFT_Entry_Address_File[node][0], self.MFT_Entry_Address_File[node][1]) + '\n'
                else: s += ' ' + '%s(%s)' %(self.MFT_Entry_Address_File[node][0], self.MFT_Entry_Address_File[node][1]) + '\n'
                s += self.__DFS(node, depth + 1)
            else:
                if depth > 0: s += '  ' * depth + '-> ' + '%s(%s)' %(self.MFT_Entry_Address_File[node][0], self.MFT_Entry_Address_File[node][1]) + '\n'
                else: s += ' ' + '%s(%s)' %(self.MFT_Entry_Address_File[node][0], self.MFT_Entry_Address_File[node][1]) + '\n'
        return s


def fileInput():
    while True:
        print('파일을 입력하세요.')
        
        FileName = filedialog.askopenfilename()
        try:
            file = open(FileName, 'rb')
            buffer = file.read(512)
            file.close()
            if buffer[0x3:0x7].decode('utf-8') != 'NTFS':
                raise Exception()
        except:
            FileName = ''
        
        if FileName != '':
            os.system('cls')
            break
        else:
            print('NTFS가 아닙니다.')
            if input('종료하시겠습니까? [yes/no] : ') == 'yes':
                print('종료합니다.')
                exit()
            else:
                os.system('cls')
    return FileName


def option1(n):
    os.system('cls')
    Type = n.getType()
    sector, cluster, VBR_Size, MFT_Offset = n.getNTFSInfo()
    print('\n\t<NTFS Informations>\t')
    print('=======================================')
    print('Type : ', Type)
    print('Sector Size : ', sector, 'bytes')
    print('Cluster Size : ', cluster, 'bytes(%d sectors)' %(cluster // sector))
    print('VBR Size : ', VBR_Size, 'bytes(%d sectors)' %(cluster // sector))
    print('MFT start Offset : ', hex(MFT_Offset))       
    # print('MFT-Entry Info : ', n.File_MFT_Entry_Address)
    # print('MFT-Entry Info : ', n.MFT_Entry_Address_File)
    # print('File Tree : ', n.FileTree)       
    print('=======================================')
    if input('Shall we go back to Main menu?[yes] : ') == 'yes':
        print('Back to Main menu')
    

def option2(n):
    os.system('cls')
    MFTArea = n.getMFTInfo()
    print('\n\t<MFT Informations>\t')
    print('=======================================')
    count = 1
    for i in MFTArea:
        print('MFT allocation part%d : %s ~ %s (%d bytes)' %(count, hex(i[0]), hex(i[1]), i[1] - i[0] + 1))
        count += 1
    print('=======================================')
    if input('Shall we go back to Main menu?[yes] : ') == 'yes':
        print('Back to Main menu')


def option3(n):
    os.system('cls')
    print('\n\t<Export Master File Table>\t')
    print('=======================================')
    n.ExportMFT()
    print('=======================================')
    if input('Shall we go back to Main menu?[yes] : ') == 'yes':
        print('Back to Main menu')


def option4(n):
    os.system('cls')
    print('\n\t<File/Directory Tree>\t')
    print('=======================================')
    n.getFileTree()
    print('=======================================')
    if input('Shall we go back to Main menu?[yes] : ') == 'yes':
        print('Back to Main menu')


def menu():
    file = fileInput()
    print('Loading...')
    ntfs = NTFS(file)
    while True:
        os.system('cls')
        print('NTFS Location : ', file)
        print('\n\t<NTFS Analysis Program>\t')
        print('=======================================')
        print('1. NTFS basic informations             ')
        print('2. Master File Table Area info         ')
        print('3. Export Master File Table            ')
        print('4. File/Directory Tree                 ')
        print('5. File analysis                       ')
        print('6. Directory analysis                  ')
        print('0. Eixt                                ')
        print('=======================================')

        option = int(input('Choose Option : '))
        if option == 1:
            option1(ntfs)
        elif option == 2:
            option2(ntfs)
        elif option == 3:
            option3(ntfs)
        elif option == 4:
            option4(ntfs)
        else:
            print('Terminates the program.')
            break    
menu()