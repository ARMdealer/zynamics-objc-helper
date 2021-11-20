import idaapi, idc, idautils
import re
import time

displ_re = re.compile('\[R(?P<regnum>\d+)')
var_re = re.compile(', \[SP,#0x.*\+(?P<varname>\w+)\]')

def trace_param(ea, min_ea, op_type, op_val):
    '''
    trace_param: ea, min_ea, op_type, op_val

    Taking ea as start, this function does basic backtrace of
    an operand (defined by op_type and op_val) until it finds
    a data reference which we consider the "source". It stops
    when ea < min_ea (usually the function start).

    It does not support arithmetic or complex modifications of
    the source. This will be improved on future versions.
    '''
    global displ_re, msgsend, var_re

    ea_call = ea
    while ea != idc.BADADDR and ea != min_ea:
        ea = idc.prev_head(ea, min_ea)

        if op_type == idaapi.o_reg and op_val == 0 and idaapi.is_call_insn(ea):
            # We have a BL/BLX that will modify the R0
            # we're tracking
            #
            return None

        if idc.print_insn_mnem(ea) in ['LDR', 'MOV']:
            src_op = 1
            dest_op = 0
        elif idc.print_insn_mnem(ea) == 'STR':
            src_op = 0
            dest_op = 1
        else:
            continue


        if idc.get_operand_type(ea, dest_op) == op_type and idc.get_operand_value(ea, dest_op) == op_val:
            # Found, see where it comes from
            if idc.get_operand_type(ea, src_op) == idc.o_mem:
                # Got the final reference
                refs = list(idautils.DataRefsFrom(ea))
                if not refs:
                    local_ref = idc.get_operand_value(ea, src_op)
                    far_ref = idc.get_wide_dword(local_ref)
                else:
                    while len(refs) > 0:
                        far_ref = refs[0]
                        refs = list(idautils.DataRefsFrom(refs[0]))
                return far_ref
            elif idc.get_operand_type(ea, src_op) == idc.o_displ:
                if ', [SP' in idc.generate_disasm_line(ea,0):
                    if 'arg_' in idc.generate_disasm_line(ea,0):
                        # We don't track function arguments
                        return None

                    # We're tracking an stack variable
                    try:
                        var_name = var_re.search(idc.generate_disasm_line(e,0)).group('varname')
                    except:
                        print ('%08x: Unable to recognize variable' % ea)
                        return None

                    while ea != idc.BADADDR and ea > min_ea:
                        if idc.print_insn_mnem(ea) == 'STR' and var_name in idc.generate_disasm_line(ea,0):
                            # New reg to track
                            op_val = idc.get_operand_value(ea, dest_op)
                            break
                        ea = idc.prev_head(ea, min_ea)
                else:
                    # New reg to track
                    if '[LR]' in idc.generate_disasm_line(ea,0):
                        # Optimizations use LR as general reg
                        op_val = 14
                    else:
                        try:
                            op_val = int(displ_re.search(idc.generate_disasm_line(ea,0)).group('regnum'))
                        except:
                            print ('%08x: Unable to recognize register' % ea)
                            return None
            elif idc.get_operand_type(ea, src_op) == idc.o_reg:
                # Direct reg-reg assignment
                op_val = idc.get_operand_value(ea, src_op)
            else:
                # We don't track o_phrase or other complex source operands :(
                return None
    return None



def fix_callgraph(msgsend, segname, class_param, sel_param):
    '''
    fix_callgraph: msgsend, segname, class_param, sel_param

    Given the msgsend flavour address as a parameter, looks
    for the parameters (class and selector, identified by
    class_param and sel_param) and creates a new segment where
    it places a set of dummy calls named as classname_methodname
    (we use method instead of selector most of the time).
    '''

    t1 = time.time()
    if not msgsend:
        print ('ERROR: msgSend not found')
        return

    total = 0
    resolved = 0
    call_table = dict()

    for xref in idautils.XrefsTo(msgsend, idaapi.XREF_ALL):
        total += 1
        ea_call = xref.frm
        func_start = idc.get_func_attr(ea_call, idc.FUNCATTR_START)
        if not func_start or func_start == idc.BADADDR:
            continue
        ea = ea_call
        method_name_ea = trace_param(ea, func_start, idc.o_reg, sel_param)
        if method_name_ea and idc.isASCII(ida_bytes.get_full_flags(method_name_ea)):
            method_name = idc.get_strlit_contents(method_name_ea, -1, idc.ASCSTR_C)
            if not method_name:
                method_name = '_unk_method'
        else:
            method_name = '_unk_method'

        class_name_ea = trace_param(ea, func_start, idc.o_reg, class_param)
        if class_name_ea:
            class_name = idc.get_name(class_name_ea, GN_DEMANGLED)
            if not class_name:
                class_name = '_unk_class'
        else:
            class_name = '_unk_class'

        if method_name == '_unk_method' and class_name == '_unk_class':
            continue

        # Using this name convention, if the class and method
        # are identified by IDA, the patched call will point to
        # the REAL call and not one of our dummy functions
        #
        class_name = class_name.replace('_OBJC_CLASS_$_', '')
        class_name = class_name.replace('_OBJC_METACLASS_$_', '')
        new_name = '_[' + class_name + '_' + method_name + ']'
        print ('%08x: %s' % (ea_call, new_name))
        call_table[ea_call] = new_name
        resolved += 1

    print ('\nFinal stats:\n\t%d total calls, %d resolved' % (total, resolved))
    print ('\tAnalysis took %.2f seconds' % (time.time() - t1))

    if resolved == 0:
        print ('Nothing to patch.')
        return

    print ('Adding new segment to store new nullsubs')

    # segment size = opcode ret (4 bytes) * num_calls
    seg_size = resolved * 4
    seg_start = ida_ida.inf_get_max_ea() + 4
    idaapi.add_segm(0, seg_start, seg_start + seg_size, segname, 'CODE')

    print ('Patching database...')
    seg_ptr = seg_start
    for ea, new_name in call_table.items():
        if idc.LocByName(new_name) != idc.BADADDR:
            offset = idc.LocByName(new_name) - ea
        else:
            # create code and name it
            ida_bytes.patch_dwordd(seg_ptr, 0xE12FFF1E) # BX LR
            idc.set_name(seg_ptr, new_name)
            idc.create_insn(seg_ptr)
            ida_funcs.add_func(seg_ptr, seg_ptr + 4)
            idc.set_cmt(seg_ptr, new_name)
            offset = seg_ptr - ea
            seg_ptr += 4

        # patch the msgsend call
        if idc.get_sreg(ea, "T") == 1:
            if offset > 0 and offset & 0xFF800000:
                print ('Offset too far for Thumb (%08x) Stopping [%08x]' % (offset, ea))
                return

            off1 = (offset & 0x7FF000) >> 12
            off2 = (offset & 0xFFF) / 2
            w1 = (0xF000 | off1)
            w2 = (0xE800 | off2) - 1
            ida_bytes.patch_word(ea, w1)
            ida_bytes.patch_word(ea + 2, w2)
        else:
            if offset > 0 and offset & 0xFF000000:
                print ('Offset too far (%08x) Stopping [%08x]' % (offset, ea))
            dw = (0xFA000000 | (offset - 8 >> 2))
            if dw < 0:
                dw = dw & 0xFAFFFFFF
            ida_bytes.patch_dword(ea, dw)


def make_offsets(segname):
    segea = idc.get_segm_by_sel(idc.selector_by_name(segname))
    segend = idc.get_segm_end(segea)

    while segea < segend:
        idc.op_plain_offset(segea, -1, 0)
        ptr = idc.get_wide_dword(segea)
        idc.op_plain_offset(ptr, -1, 0)
        segea += 4

if __name__ == '__main__':
    print ('Preparing class references segments')
    make_offsets('__objc_classrefs')
    make_offsets('__objc_superrefs')
    ida_auto.plan_and_wait(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea())
    print ('Fixing callgraph')
    fix_callgraph(idc.get_name_ea_simple('_objc_msgSend'), 'msgSend', 0, 1)
    fix_callgraph(idc.get_name_ea_simple('_objc_msgSendSuper2'), 'msgSendSuper', 3, 1)
    ida_auto.plan_and_wait(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea())
    print ('Done.')
