; ModuleID = 'xdp11_kern.c'
source_filename = "xdp11_kern.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.bpf_map_def = type { i32, i32, i32, i32, i32, i32, i32 }
%struct.xdp_md = type { i32, i32, i32, i32, i32 }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }

@rxcnt1 = dso_local global %struct.bpf_map_def { i32 6, i32 2, i32 2, i32 257, i32 0, i32 0, i32 0 }, section "maps", align 4, !dbg !0
@rxcnt2 = dso_local global %struct.bpf_map_def { i32 6, i32 8, i32 4, i32 508, i32 0, i32 0, i32 0 }, section "maps", align 4, !dbg !23
@rxcnt3 = dso_local global %struct.bpf_map_def { i32 6, i32 8, i32 8, i32 1021, i32 0, i32 0, i32 0 }, section "maps", align 4, !dbg !35
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !37
@llvm.used = appending global [5 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (%struct.bpf_map_def* @rxcnt1 to i8*), i8* bitcast (%struct.bpf_map_def* @rxcnt2 to i8*), i8* bitcast (%struct.bpf_map_def* @rxcnt3 to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_prog1 to i8*)], section "llvm.metadata"

; Function Attrs: nounwind uwtable
define dso_local i32 @xdp_prog1(%struct.xdp_md* nocapture readonly %0) #0 section "xdp1" !dbg !54 {
  %2 = alloca i32, align 4
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !68, metadata !DIExpression()), !dbg !107
  %3 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !108
  %4 = load i32, i32* %3, align 4, !dbg !108, !tbaa !109
  %5 = zext i32 %4 to i64, !dbg !114
  %6 = inttoptr i64 %5 to i8*, !dbg !115
  call void @llvm.dbg.value(metadata i8* %6, metadata !69, metadata !DIExpression()), !dbg !107
  %7 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !116
  %8 = load i32, i32* %7, align 4, !dbg !116, !tbaa !117
  %9 = zext i32 %8 to i64, !dbg !118
  %10 = inttoptr i64 %9 to i8*, !dbg !119
  call void @llvm.dbg.value(metadata i8* %10, metadata !70, metadata !DIExpression()), !dbg !107
  call void @llvm.dbg.value(metadata i8* %10, metadata !71, metadata !DIExpression()), !dbg !107
  call void @llvm.dbg.value(metadata i32 1, metadata !83, metadata !DIExpression()), !dbg !107
  %11 = bitcast i32* %2 to i8*, !dbg !120
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %11) #3, !dbg !120
  call void @llvm.dbg.value(metadata i64 14, metadata !89, metadata !DIExpression()), !dbg !107
  %12 = getelementptr i8, i8* %10, i64 14, !dbg !121
  %13 = icmp ugt i8* %12, %6, !dbg !123
  br i1 %13, label %68, label %14, !dbg !124

14:                                               ; preds = %1
  %15 = inttoptr i64 %9 to %struct.ethhdr*, !dbg !125
  call void @llvm.dbg.value(metadata %struct.ethhdr* %15, metadata !71, metadata !DIExpression()), !dbg !107
  %16 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 2, !dbg !126
  %17 = load i16, i16* %16, align 1, !dbg !126, !tbaa !127
  call void @llvm.dbg.value(metadata i16 %17, metadata !86, metadata !DIExpression()), !dbg !107
  switch i16 %17, label %25 [
    i16 129, label %18
    i16 -22392, label %18
  ], !dbg !130

18:                                               ; preds = %14, %14
  call void @llvm.dbg.value(metadata i8* %12, metadata !95, metadata !DIExpression()), !dbg !131
  call void @llvm.dbg.value(metadata i64 18, metadata !89, metadata !DIExpression()), !dbg !107
  %19 = getelementptr i8, i8* %10, i64 18, !dbg !132
  %20 = icmp ugt i8* %19, %6, !dbg !134
  br i1 %20, label %68, label %21, !dbg !135

21:                                               ; preds = %18
  call void @llvm.dbg.value(metadata i8* %12, metadata !95, metadata !DIExpression()), !dbg !131
  %22 = getelementptr i8, i8* %10, i64 16, !dbg !136
  %23 = bitcast i8* %22 to i16*, !dbg !136
  %24 = load i16, i16* %23, align 2, !dbg !136, !tbaa !137
  call void @llvm.dbg.value(metadata i16 %24, metadata !86, metadata !DIExpression()), !dbg !107
  br label %25

25:                                               ; preds = %21, %14
  %26 = phi i64 [ 14, %14 ], [ 18, %21 ], !dbg !107
  %27 = phi i16 [ %17, %14 ], [ %24, %21 ], !dbg !139
  call void @llvm.dbg.value(metadata i16 %27, metadata !86, metadata !DIExpression()), !dbg !107
  call void @llvm.dbg.value(metadata i64 %26, metadata !89, metadata !DIExpression()), !dbg !107
  switch i16 %27, label %37 [
    i16 129, label %28
    i16 -22392, label %28
  ], !dbg !140

28:                                               ; preds = %25, %25
  call void @llvm.dbg.value(metadata i8* undef, metadata !104, metadata !DIExpression()), !dbg !141
  %29 = add nuw nsw i64 %26, 4, !dbg !142
  call void @llvm.dbg.value(metadata i64 %29, metadata !89, metadata !DIExpression()), !dbg !107
  %30 = getelementptr i8, i8* %10, i64 %29, !dbg !143
  %31 = icmp ugt i8* %30, %6, !dbg !145
  br i1 %31, label %68, label %32, !dbg !146

32:                                               ; preds = %28
  %33 = getelementptr i8, i8* %10, i64 %26, !dbg !147
  call void @llvm.dbg.value(metadata i8* %33, metadata !104, metadata !DIExpression()), !dbg !141
  call void @llvm.dbg.value(metadata i8* %33, metadata !104, metadata !DIExpression()), !dbg !141
  %34 = getelementptr inbounds i8, i8* %33, i64 2, !dbg !148
  %35 = bitcast i8* %34 to i16*, !dbg !148
  %36 = load i16, i16* %35, align 2, !dbg !148, !tbaa !137
  call void @llvm.dbg.value(metadata i16 %36, metadata !86, metadata !DIExpression()), !dbg !107
  br label %37

37:                                               ; preds = %32, %25
  %38 = phi i64 [ %26, %25 ], [ %29, %32 ], !dbg !107
  %39 = phi i16 [ %27, %25 ], [ %36, %32 ], !dbg !139
  call void @llvm.dbg.value(metadata i16 %39, metadata !86, metadata !DIExpression()), !dbg !107
  call void @llvm.dbg.value(metadata i64 %38, metadata !89, metadata !DIExpression()), !dbg !107
  switch i16 %39, label %60 [
    i16 8, label %40
    i16 -8826, label %50
  ], !dbg !149

40:                                               ; preds = %37
  call void @llvm.dbg.value(metadata i8* %10, metadata !150, metadata !DIExpression()), !dbg !176
  call void @llvm.dbg.value(metadata i64 %38, metadata !155, metadata !DIExpression()), !dbg !176
  call void @llvm.dbg.value(metadata i8* %6, metadata !156, metadata !DIExpression()), !dbg !176
  %41 = getelementptr i8, i8* %10, i64 %38, !dbg !179
  call void @llvm.dbg.value(metadata i8* %41, metadata !157, metadata !DIExpression()), !dbg !176
  %42 = getelementptr inbounds i8, i8* %41, i64 20, !dbg !180
  %43 = icmp ugt i8* %42, %6, !dbg !182
  br i1 %43, label %48, label %44, !dbg !183

44:                                               ; preds = %40
  call void @llvm.dbg.value(metadata i8* %41, metadata !157, metadata !DIExpression()), !dbg !176
  %45 = getelementptr inbounds i8, i8* %41, i64 9, !dbg !184
  %46 = load i8, i8* %45, align 1, !dbg !184, !tbaa !185
  %47 = zext i8 %46 to i32, !dbg !187
  br label %48, !dbg !188

48:                                               ; preds = %40, %44
  %49 = phi i32 [ %47, %44 ], [ 0, %40 ], !dbg !176
  call void @llvm.dbg.value(metadata i32 %49, metadata !93, metadata !DIExpression()), !dbg !107
  store i32 %49, i32* %2, align 4, !dbg !189, !tbaa !190
  br label %61, !dbg !191

50:                                               ; preds = %37
  call void @llvm.dbg.value(metadata i8* %10, metadata !192, metadata !DIExpression()), !dbg !229
  call void @llvm.dbg.value(metadata i64 %38, metadata !195, metadata !DIExpression()), !dbg !229
  call void @llvm.dbg.value(metadata i8* %6, metadata !196, metadata !DIExpression()), !dbg !229
  %51 = getelementptr i8, i8* %10, i64 %38, !dbg !232
  call void @llvm.dbg.value(metadata i8* %51, metadata !197, metadata !DIExpression()), !dbg !229
  %52 = getelementptr inbounds i8, i8* %51, i64 40, !dbg !233
  %53 = icmp ugt i8* %52, %6, !dbg !235
  br i1 %53, label %58, label %54, !dbg !236

54:                                               ; preds = %50
  call void @llvm.dbg.value(metadata i8* %51, metadata !197, metadata !DIExpression()), !dbg !229
  %55 = getelementptr inbounds i8, i8* %51, i64 6, !dbg !237
  %56 = load i8, i8* %55, align 2, !dbg !237, !tbaa !238
  %57 = zext i8 %56 to i32, !dbg !241
  br label %58, !dbg !242

58:                                               ; preds = %50, %54
  %59 = phi i32 [ %57, %54 ], [ 0, %50 ], !dbg !229
  call void @llvm.dbg.value(metadata i32 %59, metadata !93, metadata !DIExpression()), !dbg !107
  store i32 %59, i32* %2, align 4, !dbg !243, !tbaa !190
  br label %61, !dbg !244

60:                                               ; preds = %37
  call void @llvm.dbg.value(metadata i32 0, metadata !93, metadata !DIExpression()), !dbg !107
  store i32 0, i32* %2, align 4, !dbg !245, !tbaa !190
  br label %61

61:                                               ; preds = %58, %60, %48
  call void @llvm.dbg.value(metadata i32* %2, metadata !93, metadata !DIExpression(DW_OP_deref)), !dbg !107
  %62 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @rxcnt1 to i8*), i8* nonnull %11) #3, !dbg !246
  %63 = bitcast i8* %62 to i64*, !dbg !246
  call void @llvm.dbg.value(metadata i64* %63, metadata !84, metadata !DIExpression()), !dbg !107
  %64 = icmp eq i8* %62, null, !dbg !247
  br i1 %64, label %68, label %65, !dbg !249

65:                                               ; preds = %61
  %66 = load i64, i64* %63, align 8, !dbg !250, !tbaa !251
  %67 = add nsw i64 %66, 1, !dbg !250
  store i64 %67, i64* %63, align 8, !dbg !250, !tbaa !251
  br label %68, !dbg !253

68:                                               ; preds = %28, %18, %65, %61, %1
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %11) #3, !dbg !254
  ret i32 1, !dbg !254
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
!llvm.module.flags = !{!50, !51, !52}
!llvm.ident = !{!53}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "rxcnt1", scope: !2, file: !3, line: 16, type: !25, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "clang version 10.0.0-4ubuntu1 ", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !14, globals: !22, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "xdp11_kern.c", directory: "/space1/zzc_data/ebpf/bintrans/resource/prog")
!4 = !{!5}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "xdp_action", file: !6, line: 3150, baseType: !7, size: 32, elements: !8)
!6 = !DIFile(filename: "linux-5.4/include/uapi/linux/bpf.h", directory: "/space1/zzc_data")
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
!18 = !DIFile(filename: "linux-5.4/include/uapi/linux/types.h", directory: "/space1/zzc_data")
!19 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !20, line: 24, baseType: !21)
!20 = !DIFile(filename: "linux-5.4/include/uapi/asm-generic/int-ll64.h", directory: "/space1/zzc_data")
!21 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!22 = !{!0, !23, !35, !37, !43}
!23 = !DIGlobalVariableExpression(var: !24, expr: !DIExpression())
!24 = distinct !DIGlobalVariable(name: "rxcnt2", scope: !2, file: !3, line: 23, type: !25, isLocal: false, isDefinition: true)
!25 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_map_def", file: !26, line: 251, size: 224, elements: !27)
!26 = !DIFile(filename: "linux-5.4/tools/testing/selftests/bpf/bpf_helpers.h", directory: "/space1/zzc_data")
!27 = !{!28, !29, !30, !31, !32, !33, !34}
!28 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !25, file: !26, line: 252, baseType: !7, size: 32)
!29 = !DIDerivedType(tag: DW_TAG_member, name: "key_size", scope: !25, file: !26, line: 253, baseType: !7, size: 32, offset: 32)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "value_size", scope: !25, file: !26, line: 254, baseType: !7, size: 32, offset: 64)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !25, file: !26, line: 255, baseType: !7, size: 32, offset: 96)
!32 = !DIDerivedType(tag: DW_TAG_member, name: "map_flags", scope: !25, file: !26, line: 256, baseType: !7, size: 32, offset: 128)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "inner_map_idx", scope: !25, file: !26, line: 257, baseType: !7, size: 32, offset: 160)
!34 = !DIDerivedType(tag: DW_TAG_member, name: "numa_node", scope: !25, file: !26, line: 258, baseType: !7, size: 32, offset: 192)
!35 = !DIGlobalVariableExpression(var: !36, expr: !DIExpression())
!36 = distinct !DIGlobalVariable(name: "rxcnt3", scope: !2, file: !3, line: 30, type: !25, isLocal: false, isDefinition: true)
!37 = !DIGlobalVariableExpression(var: !38, expr: !DIExpression())
!38 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 108, type: !39, isLocal: false, isDefinition: true)
!39 = !DICompositeType(tag: DW_TAG_array_type, baseType: !40, size: 32, elements: !41)
!40 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!41 = !{!42}
!42 = !DISubrange(count: 4)
!43 = !DIGlobalVariableExpression(var: !44, expr: !DIExpression())
!44 = distinct !DIGlobalVariable(name: "bpf_map_lookup_elem", scope: !2, file: !26, line: 25, type: !45, isLocal: true, isDefinition: true)
!45 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!46 = !DISubroutineType(types: !47)
!47 = !{!15, !15, !48}
!48 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !49, size: 64)
!49 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!50 = !{i32 7, !"Dwarf Version", i32 4}
!51 = !{i32 2, !"Debug Info Version", i32 3}
!52 = !{i32 1, !"wchar_size", i32 4}
!53 = !{!"clang version 10.0.0-4ubuntu1 "}
!54 = distinct !DISubprogram(name: "xdp_prog1", scope: !3, file: !3, line: 58, type: !55, scopeLine: 59, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !67)
!55 = !DISubroutineType(types: !56)
!56 = !{!57, !58}
!57 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!59 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !6, line: 3161, size: 160, elements: !60)
!60 = !{!61, !63, !64, !65, !66}
!61 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !59, file: !6, line: 3162, baseType: !62, size: 32)
!62 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !20, line: 27, baseType: !7)
!63 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !59, file: !6, line: 3163, baseType: !62, size: 32, offset: 32)
!64 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !59, file: !6, line: 3164, baseType: !62, size: 32, offset: 64)
!65 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !59, file: !6, line: 3166, baseType: !62, size: 32, offset: 96)
!66 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_index", scope: !59, file: !6, line: 3167, baseType: !62, size: 32, offset: 128)
!67 = !{!68, !69, !70, !71, !83, !84, !86, !89, !93, !95, !104}
!68 = !DILocalVariable(name: "ctx", arg: 1, scope: !54, file: !3, line: 58, type: !58)
!69 = !DILocalVariable(name: "data_end", scope: !54, file: !3, line: 60, type: !15)
!70 = !DILocalVariable(name: "data", scope: !54, file: !3, line: 61, type: !15)
!71 = !DILocalVariable(name: "eth", scope: !54, file: !3, line: 62, type: !72)
!72 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !73, size: 64)
!73 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ethhdr", file: !74, line: 163, size: 112, elements: !75)
!74 = !DIFile(filename: "linux-5.4/include/uapi/linux/if_ether.h", directory: "/space1/zzc_data")
!75 = !{!76, !81, !82}
!76 = !DIDerivedType(tag: DW_TAG_member, name: "h_dest", scope: !73, file: !74, line: 164, baseType: !77, size: 48)
!77 = !DICompositeType(tag: DW_TAG_array_type, baseType: !78, size: 48, elements: !79)
!78 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!79 = !{!80}
!80 = !DISubrange(count: 6)
!81 = !DIDerivedType(tag: DW_TAG_member, name: "h_source", scope: !73, file: !74, line: 165, baseType: !77, size: 48, offset: 48)
!82 = !DIDerivedType(tag: DW_TAG_member, name: "h_proto", scope: !73, file: !74, line: 166, baseType: !17, size: 16, offset: 96)
!83 = !DILocalVariable(name: "rc", scope: !54, file: !3, line: 63, type: !57)
!84 = !DILocalVariable(name: "value", scope: !54, file: !3, line: 64, type: !85)
!85 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !16, size: 64)
!86 = !DILocalVariable(name: "h_proto", scope: !54, file: !3, line: 65, type: !87)
!87 = !DIDerivedType(tag: DW_TAG_typedef, name: "u16", file: !88, line: 19, baseType: !19)
!88 = !DIFile(filename: "linux-5.4/include/asm-generic/int-ll64.h", directory: "/space1/zzc_data")
!89 = !DILocalVariable(name: "nh_off", scope: !54, file: !3, line: 66, type: !90)
!90 = !DIDerivedType(tag: DW_TAG_typedef, name: "u64", file: !88, line: 23, baseType: !91)
!91 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u64", file: !20, line: 31, baseType: !92)
!92 = !DIBasicType(name: "long long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!93 = !DILocalVariable(name: "ipproto", scope: !54, file: !3, line: 67, type: !94)
!94 = !DIDerivedType(tag: DW_TAG_typedef, name: "u32", file: !88, line: 21, baseType: !62)
!95 = !DILocalVariable(name: "vhdr", scope: !96, file: !3, line: 76, type: !98)
!96 = distinct !DILexicalBlock(scope: !97, file: !3, line: 75, column: 71)
!97 = distinct !DILexicalBlock(scope: !54, file: !3, line: 75, column: 6)
!98 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !99, size: 64)
!99 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "vlan_hdr", file: !100, line: 33, size: 32, elements: !101)
!100 = !DIFile(filename: "linux-5.4/include/linux/if_vlan.h", directory: "/space1/zzc_data")
!101 = !{!102, !103}
!102 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_TCI", scope: !99, file: !100, line: 34, baseType: !17, size: 16)
!103 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_encapsulated_proto", scope: !99, file: !100, line: 35, baseType: !17, size: 16, offset: 16)
!104 = !DILocalVariable(name: "vhdr", scope: !105, file: !3, line: 85, type: !98)
!105 = distinct !DILexicalBlock(scope: !106, file: !3, line: 84, column: 71)
!106 = distinct !DILexicalBlock(scope: !54, file: !3, line: 84, column: 6)
!107 = !DILocation(line: 0, scope: !54)
!108 = !DILocation(line: 60, column: 38, scope: !54)
!109 = !{!110, !111, i64 4}
!110 = !{!"xdp_md", !111, i64 0, !111, i64 4, !111, i64 8, !111, i64 12, !111, i64 16}
!111 = !{!"int", !112, i64 0}
!112 = !{!"omnipotent char", !113, i64 0}
!113 = !{!"Simple C/C++ TBAA"}
!114 = !DILocation(line: 60, column: 27, scope: !54)
!115 = !DILocation(line: 60, column: 19, scope: !54)
!116 = !DILocation(line: 61, column: 34, scope: !54)
!117 = !{!110, !111, i64 0}
!118 = !DILocation(line: 61, column: 23, scope: !54)
!119 = !DILocation(line: 61, column: 15, scope: !54)
!120 = !DILocation(line: 67, column: 2, scope: !54)
!121 = !DILocation(line: 70, column: 11, scope: !122)
!122 = distinct !DILexicalBlock(scope: !54, file: !3, line: 70, column: 6)
!123 = !DILocation(line: 70, column: 20, scope: !122)
!124 = !DILocation(line: 70, column: 6, scope: !54)
!125 = !DILocation(line: 62, column: 23, scope: !54)
!126 = !DILocation(line: 73, column: 17, scope: !54)
!127 = !{!128, !129, i64 12}
!128 = !{!"ethhdr", !112, i64 0, !112, i64 6, !129, i64 12}
!129 = !{!"short", !112, i64 0}
!130 = !DILocation(line: 75, column: 36, scope: !97)
!131 = !DILocation(line: 0, scope: !96)
!132 = !DILocation(line: 80, column: 12, scope: !133)
!133 = distinct !DILexicalBlock(scope: !96, file: !3, line: 80, column: 7)
!134 = !DILocation(line: 80, column: 21, scope: !133)
!135 = !DILocation(line: 80, column: 7, scope: !96)
!136 = !DILocation(line: 82, column: 19, scope: !96)
!137 = !{!138, !129, i64 2}
!138 = !{!"vlan_hdr", !129, i64 0, !129, i64 2}
!139 = !DILocation(line: 73, column: 10, scope: !54)
!140 = !DILocation(line: 84, column: 36, scope: !106)
!141 = !DILocation(line: 0, scope: !105)
!142 = !DILocation(line: 88, column: 10, scope: !105)
!143 = !DILocation(line: 89, column: 12, scope: !144)
!144 = distinct !DILexicalBlock(scope: !105, file: !3, line: 89, column: 7)
!145 = !DILocation(line: 89, column: 21, scope: !144)
!146 = !DILocation(line: 89, column: 7, scope: !105)
!147 = !DILocation(line: 87, column: 15, scope: !105)
!148 = !DILocation(line: 91, column: 19, scope: !105)
!149 = !DILocation(line: 94, column: 6, scope: !54)
!150 = !DILocalVariable(name: "data", arg: 1, scope: !151, file: !3, line: 39, type: !15)
!151 = distinct !DISubprogram(name: "parse_ipv4", scope: !3, file: !3, line: 39, type: !152, scopeLine: 40, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !154)
!152 = !DISubroutineType(types: !153)
!153 = !{!57, !15, !90, !15}
!154 = !{!150, !155, !156, !157}
!155 = !DILocalVariable(name: "nh_off", arg: 2, scope: !151, file: !3, line: 39, type: !90)
!156 = !DILocalVariable(name: "data_end", arg: 3, scope: !151, file: !3, line: 39, type: !15)
!157 = !DILocalVariable(name: "iph", scope: !151, file: !3, line: 41, type: !158)
!158 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !159, size: 64)
!159 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "iphdr", file: !160, line: 86, size: 160, elements: !161)
!160 = !DIFile(filename: "linux-5.4/include/uapi/linux/ip.h", directory: "/space1/zzc_data")
!161 = !{!162, !164, !165, !166, !167, !168, !169, !170, !171, !173, !175}
!162 = !DIDerivedType(tag: DW_TAG_member, name: "ihl", scope: !159, file: !160, line: 88, baseType: !163, size: 4, flags: DIFlagBitField, extraData: i64 0)
!163 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u8", file: !20, line: 21, baseType: !78)
!164 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !159, file: !160, line: 89, baseType: !163, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!165 = !DIDerivedType(tag: DW_TAG_member, name: "tos", scope: !159, file: !160, line: 96, baseType: !163, size: 8, offset: 8)
!166 = !DIDerivedType(tag: DW_TAG_member, name: "tot_len", scope: !159, file: !160, line: 97, baseType: !17, size: 16, offset: 16)
!167 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !159, file: !160, line: 98, baseType: !17, size: 16, offset: 32)
!168 = !DIDerivedType(tag: DW_TAG_member, name: "frag_off", scope: !159, file: !160, line: 99, baseType: !17, size: 16, offset: 48)
!169 = !DIDerivedType(tag: DW_TAG_member, name: "ttl", scope: !159, file: !160, line: 100, baseType: !163, size: 8, offset: 64)
!170 = !DIDerivedType(tag: DW_TAG_member, name: "protocol", scope: !159, file: !160, line: 101, baseType: !163, size: 8, offset: 72)
!171 = !DIDerivedType(tag: DW_TAG_member, name: "check", scope: !159, file: !160, line: 102, baseType: !172, size: 16, offset: 80)
!172 = !DIDerivedType(tag: DW_TAG_typedef, name: "__sum16", file: !18, line: 36, baseType: !19)
!173 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !159, file: !160, line: 103, baseType: !174, size: 32, offset: 96)
!174 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be32", file: !18, line: 32, baseType: !62)
!175 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !159, file: !160, line: 104, baseType: !174, size: 32, offset: 128)
!176 = !DILocation(line: 0, scope: !151, inlinedAt: !177)
!177 = distinct !DILocation(line: 95, column: 13, scope: !178)
!178 = distinct !DILexicalBlock(scope: !54, file: !3, line: 94, column: 6)
!179 = !DILocation(line: 41, column: 27, scope: !151, inlinedAt: !177)
!180 = !DILocation(line: 43, column: 10, scope: !181, inlinedAt: !177)
!181 = distinct !DILexicalBlock(scope: !151, file: !3, line: 43, column: 6)
!182 = !DILocation(line: 43, column: 14, scope: !181, inlinedAt: !177)
!183 = !DILocation(line: 43, column: 6, scope: !151, inlinedAt: !177)
!184 = !DILocation(line: 45, column: 14, scope: !151, inlinedAt: !177)
!185 = !{!186, !112, i64 9}
!186 = !{!"iphdr", !112, i64 0, !112, i64 0, !112, i64 1, !129, i64 2, !129, i64 4, !129, i64 6, !112, i64 8, !112, i64 9, !129, i64 10, !111, i64 12, !111, i64 16}
!187 = !DILocation(line: 45, column: 9, scope: !151, inlinedAt: !177)
!188 = !DILocation(line: 45, column: 2, scope: !151, inlinedAt: !177)
!189 = !DILocation(line: 95, column: 11, scope: !178)
!190 = !{!111, !111, i64 0}
!191 = !DILocation(line: 95, column: 3, scope: !178)
!192 = !DILocalVariable(name: "data", arg: 1, scope: !193, file: !3, line: 48, type: !15)
!193 = distinct !DISubprogram(name: "parse_ipv6", scope: !3, file: !3, line: 48, type: !152, scopeLine: 49, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !194)
!194 = !{!192, !195, !196, !197}
!195 = !DILocalVariable(name: "nh_off", arg: 2, scope: !193, file: !3, line: 48, type: !90)
!196 = !DILocalVariable(name: "data_end", arg: 3, scope: !193, file: !3, line: 48, type: !15)
!197 = !DILocalVariable(name: "ip6h", scope: !193, file: !3, line: 50, type: !198)
!198 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !199, size: 64)
!199 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ipv6hdr", file: !200, line: 116, size: 320, elements: !201)
!200 = !DIFile(filename: "linux-5.4/include/uapi/linux/ipv6.h", directory: "/space1/zzc_data")
!201 = !{!202, !203, !204, !208, !209, !210, !211, !228}
!202 = !DIDerivedType(tag: DW_TAG_member, name: "priority", scope: !199, file: !200, line: 118, baseType: !163, size: 4, flags: DIFlagBitField, extraData: i64 0)
!203 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !199, file: !200, line: 119, baseType: !163, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!204 = !DIDerivedType(tag: DW_TAG_member, name: "flow_lbl", scope: !199, file: !200, line: 126, baseType: !205, size: 24, offset: 8)
!205 = !DICompositeType(tag: DW_TAG_array_type, baseType: !163, size: 24, elements: !206)
!206 = !{!207}
!207 = !DISubrange(count: 3)
!208 = !DIDerivedType(tag: DW_TAG_member, name: "payload_len", scope: !199, file: !200, line: 128, baseType: !17, size: 16, offset: 32)
!209 = !DIDerivedType(tag: DW_TAG_member, name: "nexthdr", scope: !199, file: !200, line: 129, baseType: !163, size: 8, offset: 48)
!210 = !DIDerivedType(tag: DW_TAG_member, name: "hop_limit", scope: !199, file: !200, line: 130, baseType: !163, size: 8, offset: 56)
!211 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !199, file: !200, line: 132, baseType: !212, size: 128, offset: 64)
!212 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "in6_addr", file: !213, line: 33, size: 128, elements: !214)
!213 = !DIFile(filename: "linux-5.4/include/uapi/linux/in6.h", directory: "/space1/zzc_data")
!214 = !{!215}
!215 = !DIDerivedType(tag: DW_TAG_member, name: "in6_u", scope: !212, file: !213, line: 40, baseType: !216, size: 128)
!216 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !212, file: !213, line: 34, size: 128, elements: !217)
!217 = !{!218, !222, !226}
!218 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr8", scope: !216, file: !213, line: 35, baseType: !219, size: 128)
!219 = !DICompositeType(tag: DW_TAG_array_type, baseType: !163, size: 128, elements: !220)
!220 = !{!221}
!221 = !DISubrange(count: 16)
!222 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr16", scope: !216, file: !213, line: 37, baseType: !223, size: 128)
!223 = !DICompositeType(tag: DW_TAG_array_type, baseType: !17, size: 128, elements: !224)
!224 = !{!225}
!225 = !DISubrange(count: 8)
!226 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr32", scope: !216, file: !213, line: 38, baseType: !227, size: 128)
!227 = !DICompositeType(tag: DW_TAG_array_type, baseType: !174, size: 128, elements: !41)
!228 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !199, file: !200, line: 133, baseType: !212, size: 128, offset: 192)
!229 = !DILocation(line: 0, scope: !193, inlinedAt: !230)
!230 = distinct !DILocation(line: 97, column: 13, scope: !231)
!231 = distinct !DILexicalBlock(scope: !178, file: !3, line: 96, column: 11)
!232 = !DILocation(line: 50, column: 30, scope: !193, inlinedAt: !230)
!233 = !DILocation(line: 52, column: 11, scope: !234, inlinedAt: !230)
!234 = distinct !DILexicalBlock(scope: !193, file: !3, line: 52, column: 6)
!235 = !DILocation(line: 52, column: 15, scope: !234, inlinedAt: !230)
!236 = !DILocation(line: 52, column: 6, scope: !193, inlinedAt: !230)
!237 = !DILocation(line: 54, column: 15, scope: !193, inlinedAt: !230)
!238 = !{!239, !112, i64 6}
!239 = !{!"ipv6hdr", !112, i64 0, !112, i64 0, !112, i64 1, !129, i64 4, !112, i64 6, !112, i64 7, !240, i64 8, !240, i64 24}
!240 = !{!"in6_addr", !112, i64 0}
!241 = !DILocation(line: 54, column: 9, scope: !193, inlinedAt: !230)
!242 = !DILocation(line: 54, column: 2, scope: !193, inlinedAt: !230)
!243 = !DILocation(line: 97, column: 11, scope: !231)
!244 = !DILocation(line: 97, column: 3, scope: !231)
!245 = !DILocation(line: 99, column: 11, scope: !231)
!246 = !DILocation(line: 101, column: 10, scope: !54)
!247 = !DILocation(line: 102, column: 6, scope: !248)
!248 = distinct !DILexicalBlock(scope: !54, file: !3, line: 102, column: 6)
!249 = !DILocation(line: 102, column: 6, scope: !54)
!250 = !DILocation(line: 103, column: 10, scope: !248)
!251 = !{!252, !252, i64 0}
!252 = !{!"long", !112, i64 0}
!253 = !DILocation(line: 103, column: 3, scope: !248)
!254 = !DILocation(line: 106, column: 1, scope: !54)
