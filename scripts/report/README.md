# 报告生成与核验

内容由 content_team.py 与 content_personal.py 生成 JSON 和 Markdown。执行时以当前项目为根目录，不依赖开发者的绝对路径。

```bash
python3 scripts/report/content_team.py
python3 scripts/report/content_personal.py
dotnet run --project scripts/report/ReportGen.csproj -- . docs/final/documents
```

需要.NET 8或更高SDK及OpenXML SDK 3.2.0。生成器对每份DOCX执行完整OpenXML验证，验证失败即退出。文稿使用A4、宋体正文、黑体标题、连续图表编号；标题具有OutlineLevel，Word导航窗格可定位。

PDF应由同一DOCX渲染导出，再检查每页文字、图表、页码和换页。macOS无宋体/黑体时，可通过 fonts-macos.conf 映射到 Songti SC / Heiti SC；它只用于本机渲染，不包含或分发系统字体。生成环境中使用的文档渲染器需要显式继承FONTCONFIG_FILE，避免仅输出空白或方框中文。

报告源图片来自本项目浏览器验收与draw.io图。更新前端后先更新截图，再重新生成报告，不能仅修改报告日期。三份“本人核验稿”必须由对应成员依据实际执行记录核对；内容脚本中不应把未完成工作改写为已完成经历。
