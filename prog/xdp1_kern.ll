; ModuleID = 'xdp1_kern.c'
source_filename = "xdp1_kern.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.bpf_map_def = type { i32, i32, i32, i32, i32, i32, i32 }
%struct.xdp_md = type { i32, i32, i32, i32, i32 }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }

@rxcnt = dso_local global %struct.bpf_map_def { i32 6, i32 4, i32 8, i32 256, i32 0, i32 0, i32 0 }, section "maps", align 4, !dbg !0
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !23
@llvm.used = appending global [3 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (%struct.bpf_map_def* @rxcnt to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_prog1 to i8*)], section "llvm.metadata"

; Function Attrs: nounwind uwtable
define dso_local i32 @xdp_prog1(%struct.xdp_md* nocapture readonly %0) #0 section "xdp1" !dbg !50 {
  %2 = alloca i32, align 4
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !64, metadata !DIExpression()), !dbg !103
  %3 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !104
  %4 = load i32, i32* %3, align 4, !dbg !104, !tbaa !105
  %5 = zext i32 %4 to i64, !dbg !110
  %6 = inttoptr i64 %5 to i8*, !dbg !111
  call void @llvm.dbg.value(metadata i8* %6, metadata !65, metadata !DIExpression()), !dbg !103
  %7 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !112
  %8 = load i32, i32* %7, align 4, !dbg !112, !tbaa !113
  %9 = zext i32 %8 to i64, !dbg !114
  %10 = inttoptr i64 %9 to i8*, !dbg !115
  call void @llvm.dbg.value(metadata i8* %10, metadata !66, metadata !DIExpression()), !dbg !103
  call void @llvm.dbg.value(metadata i8* %10, metadata !67, metadata !DIExpression()), !dbg !103
  call void @llvm.dbg.value(metadata i32 1, metadata !79, metadata !DIExpression()), !dbg !103
  %11 = bitcast i32* %2 to i8*, !dbg !116
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %11) #3, !dbg !116
  call void @llvm.dbg.value(metadata i64 14, metadata !85, metadata !DIExpression()), !dbg !103
  %12 = getelementptr i8, i8* %10, i64 14, !dbg !117
  %13 = icmp ugt i8* %12, %6, !dbg !119
  br i1 %13, label %68, label %14, !dbg !120

14:                                               ; preds = %1
  %15 = inttoptr i64 %9 to %struct.ethhdr*, !dbg !121
  call void @llvm.dbg.value(metadata %struct.ethhdr* %15, metadata !67, metadata !DIExpression()), !dbg !103
  %16 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 2, !dbg !122
  %17 = load i16, i16* %16, align 1, !dbg !122, !tbaa !123
  call void @llvm.dbg.value(metadata i16 %17, metadata !82, metadata !DIExpression()), !dbg !103
  switch i16 %17, label %25 [
    i16 129, label %18
    i16 -22392, label %18
  ], !dbg !126

18:                                               ; preds = %14, %14
  call void @llvm.dbg.value(metadata i8* %12, metadata !91, metadata !DIExpression()), !dbg !127
  call void @llvm.dbg.value(metadata i64 18, metadata !85, metadata !DIExpression()), !dbg !103
  %19 = getelementptr i8, i8* %10, i64 18, !dbg !128
  %20 = icmp ugt i8* %19, %6, !dbg !130
  br i1 %20, label %68, label %21, !dbg !131

21:                                               ; preds = %18
  call void @llvm.dbg.value(metadata i8* %12, metadata !91, metadata !DIExpression()), !dbg !127
  %22 = getelementptr i8, i8* %10, i64 16, !dbg !132
  %23 = bitcast i8* %22 to i16*, !dbg !132
  %24 = load i16, i16* %23, align 2, !dbg !132, !tbaa !133
  call void @llvm.dbg.value(metadata i16 %24, metadata !82, metadata !DIExpression()), !dbg !103
  br label %25

25:                                               ; preds = %21, %14
  %26 = phi i64 [ 14, %14 ], [ 18, %21 ], !dbg !103
  %27 = phi i16 [ %17, %14 ], [ %24, %21 ], !dbg !135
  call void @llvm.dbg.value(metadata i16 %27, metadata !82, metadata !DIExpression()), !dbg !103
  call void @llvm.dbg.value(metadata i64 %26, metadata !85, metadata !DIExpression()), !dbg !103
  switch i16 %27, label %37 [
    i16 129, label %28
    i16 -22392, label %28
  ], !dbg !136

28:                                               ; preds = %25, %25
  call void @llvm.dbg.value(metadata i8* undef, metadata !100, metadata !DIExpression()), !dbg !137
  %29 = add nuw nsw i64 %26, 4, !dbg !138
  call void @llvm.dbg.value(metadata i64 %29, metadata !85, metadata !DIExpression()), !dbg !103
  %30 = getelementptr i8, i8* %10, i64 %29, !dbg !139
  %31 = icmp ugt i8* %30, %6, !dbg !141
  br i1 %31, label %68, label %32, !dbg !142

32:                                               ; preds = %28
  %33 = getelementptr i8, i8* %10, i64 %26, !dbg !143
  call void @llvm.dbg.value(metadata i8* %33, metadata !100, metadata !DIExpression()), !dbg !137
  call void @llvm.dbg.value(metadata i8* %33, metadata !100, metadata !DIExpression()), !dbg !137
  %34 = getelementptr inbounds i8, i8* %33, i64 2, !dbg !144
  %35 = bitcast i8* %34 to i16*, !dbg !144
  %36 = load i16, i16* %35, align 2, !dbg !144, !tbaa !133
  call void @llvm.dbg.value(metadata i16 %36, metadata !82, metadata !DIExpression()), !dbg !103
  br label %37

37:                                               ; preds = %32, %25
  %38 = phi i64 [ %26, %25 ], [ %29, %32 ], !dbg !103
  %39 = phi i16 [ %27, %25 ], [ %36, %32 ], !dbg !135
  call void @llvm.dbg.value(metadata i16 %39, metadata !82, metadata !DIExpression()), !dbg !103
  call void @llvm.dbg.value(metadata i64 %38, metadata !85, metadata !DIExpression()), !dbg !103
  switch i16 %39, label %60 [
    i16 8, label %40
    i16 -8826, label %50
  ], !dbg !145

40:                                               ; preds = %37
  call void @llvm.dbg.value(metadata i8* %10, metadata !146, metadata !DIExpression()), !dbg !172
  call void @llvm.dbg.value(metadata i64 %38, metadata !151, metadata !DIExpression()), !dbg !172
  call void @llvm.dbg.value(metadata i8* %6, metadata !152, metadata !DIExpression()), !dbg !172
  %41 = getelementptr i8, i8* %10, i64 %38, !dbg !175
  call void @llvm.dbg.value(metadata i8* %41, metadata !153, metadata !DIExpression()), !dbg !172
  %42 = getelementptr inbounds i8, i8* %41, i64 20, !dbg !176
  %43 = icmp ugt i8* %42, %6, !dbg !178
  br i1 %43, label %48, label %44, !dbg !179

44:                                               ; preds = %40
  call void @llvm.dbg.value(metadata i8* %41, metadata !153, metadata !DIExpression()), !dbg !172
  %45 = getelementptr inbounds i8, i8* %41, i64 9, !dbg !180
  %46 = load i8, i8* %45, align 1, !dbg !180, !tbaa !181
  %47 = zext i8 %46 to i32, !dbg !183
  br label %48, !dbg !184

48:                                               ; preds = %40, %44
  %49 = phi i32 [ %47, %44 ], [ 0, %40 ], !dbg !172
  call void @llvm.dbg.value(metadata i32 %49, metadata !89, metadata !DIExpression()), !dbg !103
  store i32 %49, i32* %2, align 4, !dbg !185, !tbaa !186
  br label %61, !dbg !187

50:                                               ; preds = %37
  call void @llvm.dbg.value(metadata i8* %10, metadata !188, metadata !DIExpression()), !dbg !225
  call void @llvm.dbg.value(metadata i64 %38, metadata !191, metadata !DIExpression()), !dbg !225
  call void @llvm.dbg.value(metadata i8* %6, metadata !192, metadata !DIExpression()), !dbg !225
  %51 = getelementptr i8, i8* %10, i64 %38, !dbg !228
  call void @llvm.dbg.value(metadata i8* %51, metadata !193, metadata !DIExpression()), !dbg !225
  %52 = getelementptr inbounds i8, i8* %51, i64 40, !dbg !229
  %53 = icmp ugt i8* %52, %6, !dbg !231
  br i1 %53, label %58, label %54, !dbg !232

54:                                               ; preds = %50
  call void @llvm.dbg.value(metadata i8* %51, metadata !193, metadata !DIExpression()), !dbg !225
  %55 = getelementptr inbounds i8, i8* %51, i64 6, !dbg !233
  %56 = load i8, i8* %55, align 2, !dbg !233, !tbaa !234
  %57 = zext i8 %56 to i32, !dbg !237
  br label %58, !dbg !238

58:                                               ; preds = %50, %54
  %59 = phi i32 [ %57, %54 ], [ 0, %50 ], !dbg !225
  call void @llvm.dbg.value(metadata i32 %59, metadata !89, metadata !DIExpression()), !dbg !103
  store i32 %59, i32* %2, align 4, !dbg !239, !tbaa !186
  br label %61, !dbg !240

60:                                               ; preds = %37
  call void @llvm.dbg.value(metadata i32 0, metadata !89, metadata !DIExpression()), !dbg !103
  store i32 0, i32* %2, align 4, !dbg !241, !tbaa !186
  br label %61

61:                                               ; preds = %58, %60, %48
  call void @llvm.dbg.value(metadata i32* %2, metadata !89, metadata !DIExpression(DW_OP_deref)), !dbg !103
  %62 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @rxcnt to i8*), i8* nonnull %11) #3, !dbg !242
  %63 = bitcast i8* %62 to i64*, !dbg !242
  call void @llvm.dbg.value(metadata i64* %63, metadata !80, metadata !DIExpression()), !dbg !103
  %64 = icmp eq i8* %62, null, !dbg !243
  br i1 %64, label %68, label %65, !dbg !245

65:                                               ; preds = %61
  %66 = load i64, i64* %63, align 8, !dbg !246, !tbaa !247
  %67 = add nsw i64 %66, 1, !dbg !246
  store i64 %67, i64* %63, align 8, !dbg !246, !tbaa !247
  br label %68, !dbg !249

68:                                               ; preds = %28, %18, %65, %61, %1
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %11) #3, !dbg !250
  ret i32 1, !dbg !250
}

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #1

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #1

; Function Attrs: nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #2

attributes #0 = { nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { argmemonly nounwind willreturn }
attributes #2 = { nounwind readnone speculatable willreturn }
attributes #3 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!46, !47, !48}
!llvm.ident = !{!49}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "rxcnt", scope: !2, file: !3, line: 11, type: !37, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "clang version 10.0.0-4ubuntu1 ", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !14, globals: !22, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "xdp1_kern.c", directory: "/home/zzc/project/code/ebpf/binTrans/prog")
!4 = !{!5}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "xdp_action", file: !6, line: 3150, baseType: !7, size: 32, elements: !8)
!6 = !DIFile(filename: "/space1/zzc_data/linux-5.4/include/uapi/linux/bpf.h", directory: "")
!7 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!8 = !{!9, !10, !11, !12, !13}
!9 = !DIEnumerator(name: "XDP_ABORTED", value: 0, isUnsigned: true)
!10 = !DIEnumerator(name: "XDP_DROP", value: 1, isUnsigned: true)
!11 = !DIEnumerator(name: "XDP_PASS", value: 2, isUnsigned: true)
!12 = !DIEnumerator(name: "XDP_TX", value: 3, isUnsigned: true)
!13 = !DIEnumerator(name: "XDP_REDIRECT", value: 4, isUnsigned: true)
!14 = !{!15, !16, !17, !19}
!15 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!16 = !DIBasicType(name: "long int", size: 64, encoding: DW_ATE_signed)
!17 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be16", file: !18, line: 30, baseType: !19)
!18 = !DIFile(filename: "/space1/zzc_data/linux-5.4/include/uapi/linux/types.h", directory: "")
!19 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !20, line: 24, baseType: !21)
!20 = !DIFile(filename: "/space1/zzc_data/linux-5.4/include/uapi/asm-generic/int-ll64.h", directory: "")
!21 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!22 = !{!0, !23, !29}
!23 = !DIGlobalVariableExpression(var: !24, expr: !DIExpression())
!24 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 87, type: !25, isLocal: false, isDefinition: true)
!25 = !DICompositeType(tag: DW_TAG_array_type, baseType: !26, size: 32, elements: !27)
!26 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!27 = !{!28}
!28 = !DISubrange(count: 4)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "bpf_map_lookup_elem", scope: !2, file: !31, line: 25, type: !32, isLocal: true, isDefinition: true)
!31 = !DIFile(filename: "/space1/zzc_data/linux-5.4/tools/testing/selftests/bpf/bpf_helpers.h", directory: "")
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DISubroutineType(types: !34)
!34 = !{!15, !15, !35}
!35 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !36, size: 64)
!36 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!37 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_map_def", file: !31, line: 251, size: 224, elements: !38)
!38 = !{!39, !40, !41, !42, !43, !44, !45}
!39 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !37, file: !31, line: 252, baseType: !7, size: 32)
!40 = !DIDerivedType(tag: DW_TAG_member, name: "key_size", scope: !37, file: !31, line: 253, baseType: !7, size: 32, offset: 32)
!41 = !DIDerivedType(tag: DW_TAG_member, name: "value_size", scope: !37, file: !31, line: 254, baseType: !7, size: 32, offset: 64)
!42 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !37, file: !31, line: 255, baseType: !7, size: 32, offset: 96)
!43 = !DIDerivedType(tag: DW_TAG_member, name: "map_flags", scope: !37, file: !31, line: 256, baseType: !7, size: 32, offset: 128)
!44 = !DIDerivedType(tag: DW_TAG_member, name: "inner_map_idx", scope: !37, file: !31, line: 257, baseType: !7, size: 32, offset: 160)
!45 = !DIDerivedType(tag: DW_TAG_member, name: "numa_node", scope: !37, file: !31, line: 258, baseType: !7, size: 32, offset: 192)
!46 = !{i32 7, !"Dwarf Version", i32 4}
!47 = !{i32 2, !"Debug Info Version", i32 3}
!48 = !{i32 1, !"wchar_size", i32 4}
!49 = !{!"clang version 10.0.0-4ubuntu1 "}
!50 = distinct !DISubprogram(name: "xdp_prog1", scope: !3, file: !3, line: 37, type: !51, scopeLine: 38, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !63)
!51 = !DISubroutineType(types: !52)
!52 = !{!53, !54}
!53 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !6, line: 3161, size: 160, elements: !56)
!56 = !{!57, !59, !60, !61, !62}
!57 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !55, file: !6, line: 3162, baseType: !58, size: 32)
!58 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !20, line: 27, baseType: !7)
!59 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !55, file: !6, line: 3163, baseType: !58, size: 32, offset: 32)
!60 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !55, file: !6, line: 3164, baseType: !58, size: 32, offset: 64)
!61 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !55, file: !6, line: 3166, baseType: !58, size: 32, offset: 96)
!62 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_index", scope: !55, file: !6, line: 3167, baseType: !58, size: 32, offset: 128)
!63 = !{!64, !65, !66, !67, !79, !80, !82, !85, !89, !91, !100}
!64 = !DILocalVariable(name: "ctx", arg: 1, scope: !50, file: !3, line: 37, type: !54)
!65 = !DILocalVariable(name: "data_end", scope: !50, file: !3, line: 39, type: !15)
!66 = !DILocalVariable(name: "data", scope: !50, file: !3, line: 40, type: !15)
!67 = !DILocalVariable(name: "eth", scope: !50, file: !3, line: 41, type: !68)
!68 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !69, size: 64)
!69 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ethhdr", file: !70, line: 163, size: 112, elements: !71)
!70 = !DIFile(filename: "/space1/zzc_data/linux-5.4/include/uapi/linux/if_ether.h", directory: "")
!71 = !{!72, !77, !78}
!72 = !DIDerivedType(tag: DW_TAG_member, name: "h_dest", scope: !69, file: !70, line: 164, baseType: !73, size: 48)
!73 = !DICompositeType(tag: DW_TAG_array_type, baseType: !74, size: 48, elements: !75)
!74 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!75 = !{!76}
!76 = !DISubrange(count: 6)
!77 = !DIDerivedType(tag: DW_TAG_member, name: "h_source", scope: !69, file: !70, line: 165, baseType: !73, size: 48, offset: 48)
!78 = !DIDerivedType(tag: DW_TAG_member, name: "h_proto", scope: !69, file: !70, line: 166, baseType: !17, size: 16, offset: 96)
!79 = !DILocalVariable(name: "rc", scope: !50, file: !3, line: 42, type: !53)
!80 = !DILocalVariable(name: "value", scope: !50, file: !3, line: 43, type: !81)
!81 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !16, size: 64)
!82 = !DILocalVariable(name: "h_proto", scope: !50, file: !3, line: 44, type: !83)
!83 = !DIDerivedType(tag: DW_TAG_typedef, name: "u16", file: !84, line: 19, baseType: !19)
!84 = !DIFile(filename: "/space1/zzc_data/linux-5.4/include/asm-generic/int-ll64.h", directory: "")
!85 = !DILocalVariable(name: "nh_off", scope: !50, file: !3, line: 45, type: !86)
!86 = !DIDerivedType(tag: DW_TAG_typedef, name: "u64", file: !84, line: 23, baseType: !87)
!87 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u64", file: !20, line: 31, baseType: !88)
!88 = !DIBasicType(name: "long long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!89 = !DILocalVariable(name: "ipproto", scope: !50, file: !3, line: 46, type: !90)
!90 = !DIDerivedType(tag: DW_TAG_typedef, name: "u32", file: !84, line: 21, baseType: !58)
!91 = !DILocalVariable(name: "vhdr", scope: !92, file: !3, line: 55, type: !94)
!92 = distinct !DILexicalBlock(scope: !93, file: !3, line: 54, column: 71)
!93 = distinct !DILexicalBlock(scope: !50, file: !3, line: 54, column: 6)
!94 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !95, size: 64)
!95 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "vlan_hdr", file: !96, line: 33, size: 32, elements: !97)
!96 = !DIFile(filename: "/space1/zzc_data/linux-5.4/include/linux/if_vlan.h", directory: "")
!97 = !{!98, !99}
!98 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_TCI", scope: !95, file: !96, line: 34, baseType: !17, size: 16)
!99 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_encapsulated_proto", scope: !95, file: !96, line: 35, baseType: !17, size: 16, offset: 16)
!100 = !DILocalVariable(name: "vhdr", scope: !101, file: !3, line: 64, type: !94)
!101 = distinct !DILexicalBlock(scope: !102, file: !3, line: 63, column: 71)
!102 = distinct !DILexicalBlock(scope: !50, file: !3, line: 63, column: 6)
!103 = !DILocation(line: 0, scope: !50)
!104 = !DILocation(line: 39, column: 38, scope: !50)
!105 = !{!106, !107, i64 4}
!106 = !{!"xdp_md", !107, i64 0, !107, i64 4, !107, i64 8, !107, i64 12, !107, i64 16}
!107 = !{!"int", !108, i64 0}
!108 = !{!"omnipotent char", !109, i64 0}
!109 = !{!"Simple C/C++ TBAA"}
!110 = !DILocation(line: 39, column: 27, scope: !50)
!111 = !DILocation(line: 39, column: 19, scope: !50)
!112 = !DILocation(line: 40, column: 34, scope: !50)
!113 = !{!106, !107, i64 0}
!114 = !DILocation(line: 40, column: 23, scope: !50)
!115 = !DILocation(line: 40, column: 15, scope: !50)
!116 = !DILocation(line: 46, column: 2, scope: !50)
!117 = !DILocation(line: 49, column: 11, scope: !118)
!118 = distinct !DILexicalBlock(scope: !50, file: !3, line: 49, column: 6)
!119 = !DILocation(line: 49, column: 20, scope: !118)
!120 = !DILocation(line: 49, column: 6, scope: !50)
!121 = !DILocation(line: 41, column: 23, scope: !50)
!122 = !DILocation(line: 52, column: 17, scope: !50)
!123 = !{!124, !125, i64 12}
!124 = !{!"ethhdr", !108, i64 0, !108, i64 6, !125, i64 12}
!125 = !{!"short", !108, i64 0}
!126 = !DILocation(line: 54, column: 36, scope: !93)
!127 = !DILocation(line: 0, scope: !92)
!128 = !DILocation(line: 59, column: 12, scope: !129)
!129 = distinct !DILexicalBlock(scope: !92, file: !3, line: 59, column: 7)
!130 = !DILocation(line: 59, column: 21, scope: !129)
!131 = !DILocation(line: 59, column: 7, scope: !92)
!132 = !DILocation(line: 61, column: 19, scope: !92)
!133 = !{!134, !125, i64 2}
!134 = !{!"vlan_hdr", !125, i64 0, !125, i64 2}
!135 = !DILocation(line: 52, column: 10, scope: !50)
!136 = !DILocation(line: 63, column: 36, scope: !102)
!137 = !DILocation(line: 0, scope: !101)
!138 = !DILocation(line: 67, column: 10, scope: !101)
!139 = !DILocation(line: 68, column: 12, scope: !140)
!140 = distinct !DILexicalBlock(scope: !101, file: !3, line: 68, column: 7)
!141 = !DILocation(line: 68, column: 21, scope: !140)
!142 = !DILocation(line: 68, column: 7, scope: !101)
!143 = !DILocation(line: 66, column: 15, scope: !101)
!144 = !DILocation(line: 70, column: 19, scope: !101)
!145 = !DILocation(line: 73, column: 6, scope: !50)
!146 = !DILocalVariable(name: "data", arg: 1, scope: !147, file: !3, line: 18, type: !15)
!147 = distinct !DISubprogram(name: "parse_ipv4", scope: !3, file: !3, line: 18, type: !148, scopeLine: 19, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !150)
!148 = !DISubroutineType(types: !149)
!149 = !{!53, !15, !86, !15}
!150 = !{!146, !151, !152, !153}
!151 = !DILocalVariable(name: "nh_off", arg: 2, scope: !147, file: !3, line: 18, type: !86)
!152 = !DILocalVariable(name: "data_end", arg: 3, scope: !147, file: !3, line: 18, type: !15)
!153 = !DILocalVariable(name: "iph", scope: !147, file: !3, line: 20, type: !154)
!154 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !155, size: 64)
!155 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "iphdr", file: !156, line: 86, size: 160, elements: !157)
!156 = !DIFile(filename: "/space1/zzc_data/linux-5.4/include/uapi/linux/ip.h", directory: "")
!157 = !{!158, !160, !161, !162, !163, !164, !165, !166, !167, !169, !171}
!158 = !DIDerivedType(tag: DW_TAG_member, name: "ihl", scope: !155, file: !156, line: 88, baseType: !159, size: 4, flags: DIFlagBitField, extraData: i64 0)
!159 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u8", file: !20, line: 21, baseType: !74)
!160 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !155, file: !156, line: 89, baseType: !159, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!161 = !DIDerivedType(tag: DW_TAG_member, name: "tos", scope: !155, file: !156, line: 96, baseType: !159, size: 8, offset: 8)
!162 = !DIDerivedType(tag: DW_TAG_member, name: "tot_len", scope: !155, file: !156, line: 97, baseType: !17, size: 16, offset: 16)
!163 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !155, file: !156, line: 98, baseType: !17, size: 16, offset: 32)
!164 = !DIDerivedType(tag: DW_TAG_member, name: "frag_off", scope: !155, file: !156, line: 99, baseType: !17, size: 16, offset: 48)
!165 = !DIDerivedType(tag: DW_TAG_member, name: "ttl", scope: !155, file: !156, line: 100, baseType: !159, size: 8, offset: 64)
!166 = !DIDerivedType(tag: DW_TAG_member, name: "protocol", scope: !155, file: !156, line: 101, baseType: !159, size: 8, offset: 72)
!167 = !DIDerivedType(tag: DW_TAG_member, name: "check", scope: !155, file: !156, line: 102, baseType: !168, size: 16, offset: 80)
!168 = !DIDerivedType(tag: DW_TAG_typedef, name: "__sum16", file: !18, line: 36, baseType: !19)
!169 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !155, file: !156, line: 103, baseType: !170, size: 32, offset: 96)
!170 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be32", file: !18, line: 32, baseType: !58)
!171 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !155, file: !156, line: 104, baseType: !170, size: 32, offset: 128)
!172 = !DILocation(line: 0, scope: !147, inlinedAt: !173)
!173 = distinct !DILocation(line: 74, column: 13, scope: !174)
!174 = distinct !DILexicalBlock(scope: !50, file: !3, line: 73, column: 6)
!175 = !DILocation(line: 20, column: 27, scope: !147, inlinedAt: !173)
!176 = !DILocation(line: 22, column: 10, scope: !177, inlinedAt: !173)
!177 = distinct !DILexicalBlock(scope: !147, file: !3, line: 22, column: 6)
!178 = !DILocation(line: 22, column: 14, scope: !177, inlinedAt: !173)
!179 = !DILocation(line: 22, column: 6, scope: !147, inlinedAt: !173)
!180 = !DILocation(line: 24, column: 14, scope: !147, inlinedAt: !173)
!181 = !{!182, !108, i64 9}
!182 = !{!"iphdr", !108, i64 0, !108, i64 0, !108, i64 1, !125, i64 2, !125, i64 4, !125, i64 6, !108, i64 8, !108, i64 9, !125, i64 10, !107, i64 12, !107, i64 16}
!183 = !DILocation(line: 24, column: 9, scope: !147, inlinedAt: !173)
!184 = !DILocation(line: 24, column: 2, scope: !147, inlinedAt: !173)
!185 = !DILocation(line: 74, column: 11, scope: !174)
!186 = !{!107, !107, i64 0}
!187 = !DILocation(line: 74, column: 3, scope: !174)
!188 = !DILocalVariable(name: "data", arg: 1, scope: !189, file: !3, line: 27, type: !15)
!189 = distinct !DISubprogram(name: "parse_ipv6", scope: !3, file: !3, line: 27, type: !148, scopeLine: 28, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !190)
!190 = !{!188, !191, !192, !193}
!191 = !DILocalVariable(name: "nh_off", arg: 2, scope: !189, file: !3, line: 27, type: !86)
!192 = !DILocalVariable(name: "data_end", arg: 3, scope: !189, file: !3, line: 27, type: !15)
!193 = !DILocalVariable(name: "ip6h", scope: !189, file: !3, line: 29, type: !194)
!194 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !195, size: 64)
!195 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ipv6hdr", file: !196, line: 116, size: 320, elements: !197)
!196 = !DIFile(filename: "/space1/zzc_data/linux-5.4/include/uapi/linux/ipv6.h", directory: "")
!197 = !{!198, !199, !200, !204, !205, !206, !207, !224}
!198 = !DIDerivedType(tag: DW_TAG_member, name: "priority", scope: !195, file: !196, line: 118, baseType: !159, size: 4, flags: DIFlagBitField, extraData: i64 0)
!199 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !195, file: !196, line: 119, baseType: !159, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!200 = !DIDerivedType(tag: DW_TAG_member, name: "flow_lbl", scope: !195, file: !196, line: 126, baseType: !201, size: 24, offset: 8)
!201 = !DICompositeType(tag: DW_TAG_array_type, baseType: !159, size: 24, elements: !202)
!202 = !{!203}
!203 = !DISubrange(count: 3)
!204 = !DIDerivedType(tag: DW_TAG_member, name: "payload_len", scope: !195, file: !196, line: 128, baseType: !17, size: 16, offset: 32)
!205 = !DIDerivedType(tag: DW_TAG_member, name: "nexthdr", scope: !195, file: !196, line: 129, baseType: !159, size: 8, offset: 48)
!206 = !DIDerivedType(tag: DW_TAG_member, name: "hop_limit", scope: !195, file: !196, line: 130, baseType: !159, size: 8, offset: 56)
!207 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !195, file: !196, line: 132, baseType: !208, size: 128, offset: 64)
!208 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "in6_addr", file: !209, line: 33, size: 128, elements: !210)
!209 = !DIFile(filename: "/space1/zzc_data/linux-5.4/include/uapi/linux/in6.h", directory: "")
!210 = !{!211}
!211 = !DIDerivedType(tag: DW_TAG_member, name: "in6_u", scope: !208, file: !209, line: 40, baseType: !212, size: 128)
!212 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !208, file: !209, line: 34, size: 128, elements: !213)
!213 = !{!214, !218, !222}
!214 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr8", scope: !212, file: !209, line: 35, baseType: !215, size: 128)
!215 = !DICompositeType(tag: DW_TAG_array_type, baseType: !159, size: 128, elements: !216)
!216 = !{!217}
!217 = !DISubrange(count: 16)
!218 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr16", scope: !212, file: !209, line: 37, baseType: !219, size: 128)
!219 = !DICompositeType(tag: DW_TAG_array_type, baseType: !17, size: 128, elements: !220)
!220 = !{!221}
!221 = !DISubrange(count: 8)
!222 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr32", scope: !212, file: !209, line: 38, baseType: !223, size: 128)
!223 = !DICompositeType(tag: DW_TAG_array_type, baseType: !170, size: 128, elements: !27)
!224 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !195, file: !196, line: 133, baseType: !208, size: 128, offset: 192)
!225 = !DILocation(line: 0, scope: !189, inlinedAt: !226)
!226 = distinct !DILocation(line: 76, column: 13, scope: !227)
!227 = distinct !DILexicalBlock(scope: !174, file: !3, line: 75, column: 11)
!228 = !DILocation(line: 29, column: 30, scope: !189, inlinedAt: !226)
!229 = !DILocation(line: 31, column: 11, scope: !230, inlinedAt: !226)
!230 = distinct !DILexicalBlock(scope: !189, file: !3, line: 31, column: 6)
!231 = !DILocation(line: 31, column: 15, scope: !230, inlinedAt: !226)
!232 = !DILocation(line: 31, column: 6, scope: !189, inlinedAt: !226)
!233 = !DILocation(line: 33, column: 15, scope: !189, inlinedAt: !226)
!234 = !{!235, !108, i64 6}
!235 = !{!"ipv6hdr", !108, i64 0, !108, i64 0, !108, i64 1, !125, i64 4, !108, i64 6, !108, i64 7, !236, i64 8, !236, i64 24}
!236 = !{!"in6_addr", !108, i64 0}
!237 = !DILocation(line: 33, column: 9, scope: !189, inlinedAt: !226)
!238 = !DILocation(line: 33, column: 2, scope: !189, inlinedAt: !226)
!239 = !DILocation(line: 76, column: 11, scope: !227)
!240 = !DILocation(line: 76, column: 3, scope: !227)
!241 = !DILocation(line: 78, column: 11, scope: !227)
!242 = !DILocation(line: 80, column: 10, scope: !50)
!243 = !DILocation(line: 81, column: 6, scope: !244)
!244 = distinct !DILexicalBlock(scope: !50, file: !3, line: 81, column: 6)
!245 = !DILocation(line: 81, column: 6, scope: !50)
!246 = !DILocation(line: 82, column: 10, scope: !244)
!247 = !{!248, !248, i64 0}
!248 = !{!"long", !108, i64 0}
!249 = !DILocation(line: 82, column: 3, scope: !244)
!250 = !DILocation(line: 85, column: 1, scope: !50)
