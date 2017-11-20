#pragma once

const char* idb_events_strings[] = {
	//enum event_code_t
	"byte_patched",   //0
	"cmt_changed",   //1
	"ti_changed",   //2
	"op_ti_changed",   //3
	"op_type_changed",   //4
	"enum_created",   //5
	"enum_deleted",   //6
	"enum_bf_changed",   //7
	"enum_renamed",   //8
	"enum_cmt_changed",   //9
#ifndef NO_OBSOLETE_FUNCS
	"enum_const_created",   //10
	"enum_const_deleted",   //11
#else
	"enum_member_created",   //10
	"enum_member_deleted",   //11
#endif
	"struc_created",   //12
	"struc_deleted",   //13
	"struc_renamed",   //14
	"struc_expanded",   //15
	"struc_cmt_changed",   //16
	"struc_member_created",   //17
	"struc_member_deleted",   //18
	"struc_member_renamed",   //19
	"struc_member_changed",   //20
	"thunk_func_created",   //21
	"func_tail_appended",   //22
	"func_tail_removed",   //23
	"tail_owner_changed",   //24
	"func_noret_changed",   //25
	"segm_added",   //26
	"segm_deleted",   //27
	"segm_start_changed",   //28
	"segm_end_changed",   //29
	"segm_moved",   //30
	"area_cmt_changed",   //31
	"changing_cmt",   //32
	"changing_ti",   //33
	"changing_op_ti",   //34
	"changing_op_type",   //35
	"deleting_enum",   //36
	"changing_enum_bf",   //37
	"renaming_enum",   //38
	"changing_enum_cmt",   //39
#ifndef NO_OBSOLETE_FUNCS
	"deleting_enum_const",   //40
#else
	"deleting_enum_member",   //40
#endif
	"deleting_struc",   //41
	"renaming_struc",   //42
	"expanding_struc",   //43
	"changing_struc_cmt",   //44
	"deleting_struc_member",   //45
	"renaming_struc_member",   //46
	"changing_struc_member",   //47
	"removing_func_tail",   //48
	"deleting_segm",   //49
	"changing_segm_start",   //50
	"changing_segm_end",   //51
	"changing_area_cmt",   //52
	"changing_segm_name",   //53
	"changing_segm_class",   //54
	"segm_name_changed",   //55
	"segm_class_changed",   //56
	"destroyed_items",   //57
	"changed_stkpnts",   //58
	"extra_cmt_changed",  //59
	"changing_struc",	//60
	"changed_struc",	//61
	"local_types_changed",	//62
	"segm_attrs_changed"	//63
};