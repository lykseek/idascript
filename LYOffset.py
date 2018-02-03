import idaapi

class lyoffset(idaapi.plugin_t):
	flags=idaapi.PLUGIN_UNL
	comment = "This is a offset plugin"

	help="This is a offset plugin"
	wanted_name="LYOffset"
	wanted_hotkey="Shift-1"

	def init(slef):
		return idaapi.PLUGIN_OK

	def run(self,arg):
		ea=here()
		start=idc.get_segm_attr(ea,SEGATTR_START)
		name=idc.get_segm_name(ea)
		msg="%s:%x offset:%x \n" % (name,start,ea-start)

		idaapi.msg(msg)

	def term(self):
		pass

def PLUGIN_ENTRY():
    return lyoffset()

