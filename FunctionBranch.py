import idaapi
import idautils
import idc

class FunctionBranch(object):
	"""Catch branch code ,then do breakpoint"""

	def __init__(self, arg):
		super(FunctionBranch, self).__init__()
		self.arg = arg

	def init(self):
		self.ea=here()
		self.func=idc.get_func_attr(self.ea,FUNCATTR_START)
		self.funcEnd=idc.get_func_attr(self.ea,FUNCATTR_END) - 4
		self.path="E:\\ida\\fifa\\branches.txt"
		self.file=open(self.path,"a+")
		print "Func %x -- %x " % (self.func,self.funcEnd)

	def term(self):
		self.file.close()

	def run(self):
		idaapi.msg("Function Branch!!\n")
		self.init()
		self.iterInstructions()
		self.term()

	def writeFile(self,str):
		self.file.write(str)
		self.file.flush()

	def isCycle(self,addr):
		eb=addr-8
		m=idc.generate_disasm_line(eb,0)
		if m.startswith("LDREX") or m.startswith("STREX"):
			return True
		return False

	def iterInstructions(self):
		self.writeFile("*"*80)
		self.writeFile("\n")
		name=idc.get_func_name(self.ea)
		msg="Func:%s \n" % name
		idaapi.msg(msg)
		self.writeFile(msg)

		dismAddr=list(idautils.FuncItems(self.ea))
		for addr in dismAddr:
			m=idc.generate_disasm_line(addr,0)			
			if m.startswith("BNE") or m.startswith("BE") or m.startswith("BLT") or m.startswith("BHI"):
				if not self.isCycle(addr):
					msg="Branch:%X, %s \n" % (addr,m)
					idaapi.msg(msg)			
					self.writeFile(msg)
					self.addTracePoint(addr)
			elif m.startswith("BLX") or m.startswith("BL") or m.startswith("BX"):
				msg="Call:%X, %s \n" % (addr,m)
				idaapi.msg(msg)
				self.writeFile(msg)
				# self.addBreakPoint(addr)
			elif m.startswith("LDMFD"):
				msg="Ret:%X, %s \n" % (addr,m)
				idaapi.msg(msg)
				self.writeFile(msg)				
				self.addBreakPoint(addr)
			elif m.startswith("BXNE") and "LR" in m:
				msg="Ret:%X, %s \n" % (addr,m)
				idaapi.msg(msg)
				self.writeFile(msg)				
				self.addBreakPoint(addr)
			elif m.startswith("BXEQ") and "LR" in m:
				msg="Ret:%X, %s \n" % (addr,m)
				idaapi.msg(msg)
				self.writeFile(msg)				
				self.addBreakPoint(addr)

		self.addBreakPoint(self.func)
		self.addBreakPoint(self.funcEnd)

	def addBreakPoint(self,addr):
		idc.add_bpt(addr)
		idc.enable_bpt(addr,True)

	def addTracePoint(self,addr):
		idc.add_bpt(addr)
		idc.set_bpt_attr(addr,BPTATTR_FLAGS,BPT_TRACE)
		idc.enable_bpt(addr,True)			

funcBranch=FunctionBranch(0)
funcBranch.run()
