// Reproducible Chinese report builder: JSON blocks -> validated OpenXML DOCX.
using System.Text.Json;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Validation;
using DocumentFormat.OpenXml.Wordprocessing;
using A = DocumentFormat.OpenXml.Drawing;
using DW = DocumentFormat.OpenXml.Drawing.Wordprocessing;
using PIC = DocumentFormat.OpenXml.Drawing.Pictures;

internal static class Program
{
    private const int Width = 9026;
    private static uint imageId = 1;
    private static string Root = "";
    static void Main(string[] args)
    {
        Root = Path.GetFullPath(args.Length > 0 ? args[0] : ".");
        var source = Path.Combine(Root, "docs", "final");
        var output = args.Length > 1 ? Path.GetFullPath(args[1]) : Path.Combine(source, "documents");
        Directory.CreateDirectory(output);
        // Optional third argument builds a single guide without rewriting the submitted reports.
        IEnumerable<string> inputs = args.Length > 2 ? new[] { Path.GetFullPath(args[2]) } : Directory.GetFiles(source, "*.json").Order();
        foreach (var path in inputs)
        {
            using var json = JsonDocument.Parse(File.ReadAllText(path));
            var spec = json.RootElement;
            if (!spec.TryGetProperty("blocks", out var blocks)) continue;
            var filename = Path.Combine(output, spec.GetProperty("filename").GetString()!);
            using var doc = WordprocessingDocument.Create(filename, WordprocessingDocumentType.Document);
            doc.PackageProperties.Title = spec.GetProperty("title").GetString();
            doc.PackageProperties.Creator = spec.GetProperty("author").GetString();
            var main = doc.AddMainDocumentPart(); main.Document = new Document(new Body());
            bool compactLayout = spec.TryGetProperty("compact", out var compact) && compact.GetBoolean();
            AddStyles(main, compactLayout);
            main.AddNewPart<DocumentSettingsPart>().Settings = new Settings(new UpdateFieldsOnOpen { Val = true });
            var body = main.Document.Body!;
            bool cover = spec.GetProperty("cover").GetBoolean();
            var title = Paragraph(spec.GetProperty("title").GetString()!, "Title");
            if (cover) title.ParagraphProperties!.Append(new SpacingBetweenLines { Before = "1600", After = "480", Line = "360", LineRule = LineSpacingRuleValues.Auto });
            body.Append(title);
            body.Append(Paragraph(spec.GetProperty("kind").GetString()!, "Subtitle"));
            body.Append(Paragraph(spec.GetProperty("author").GetString()!, "Subtitle"));
            if (cover)
            {
                body.Append(Paragraph("网络空间安全专业  网安2302班", "Subtitle"));
                body.Append(Paragraph("应用软件开发课程设计", "Subtitle"));
                body.Append(Paragraph("2026年9月23日", "Subtitle"));
                Page(body);
                body.Append(Paragraph("目录", "Heading1"));
                foreach (var block in blocks.EnumerateArray())
                    if (block.GetProperty("type").GetString() == "h" && block.GetProperty("level").GetInt32() == 1)
                    {
                        var headingText = block.GetProperty("text").GetString()!;
                        var entry = Paragraph(headingText, "Contents");
                        if (spec.TryGetProperty("toc_pages", out var toc) && toc.TryGetProperty(headingText, out var page))
                        {
                            entry.ParagraphProperties!.Append(new Tabs(new TabStop { Val=TabStopValues.Right, Leader=TabStopLeaderCharValues.Dot, Position=Width }));
                            entry.Append(new Run(new TabChar()), TextRun(page.GetInt32().ToString()));
                        }
                        body.Append(entry);
                    }
                body.Append(Paragraph("目录按正文顺序列出。Word 导航窗格可按标题定位章节。", "Small"));
                Page(body);
            }
            bool breakBeforeHeading = false;
            foreach (var block in blocks.EnumerateArray())
            {
                switch (block.GetProperty("type").GetString())
                {
                    case "h":
                        var h = Paragraph(block.GetProperty("text").GetString()!, "Heading" + block.GetProperty("level").GetInt32());
                        if (breakBeforeHeading) { h.ParagraphProperties!.Append(new PageBreakBefore()); breakBeforeHeading = false; }
                        body.Append(h); break;
                    case "p": body.Append(Paragraph(block.GetProperty("text").GetString()!, "Normal")); break;
                    case "code":
                        var lines = block.GetProperty("text").GetString()!.Split('\n');
                        for (int i = 0; i < lines.Length; i++)
                        {
                            var code = Paragraph(lines[i], "Code");
                            if (i < lines.Length - 1) code.ParagraphProperties!.Append(new KeepNext());
                            body.Append(code);
                        }
                        break;
                    case "page":
                        if (compactLayout) breakBeforeHeading = true;
                        else Page(body);
                        break;
                    case "table":
                        var caption = Paragraph(block.GetProperty("caption").GetString()!, "Caption");
                        caption.ParagraphProperties!.Append(new KeepNext()); body.Append(caption);
                        body.Append(MakeTable(block, compactLayout)); break;
                    case "image":
                        AddImage(main, body, Path.Combine(Root, block.GetProperty("path").GetString()!), block.GetProperty("caption").GetString()!);
                        body.Append(Paragraph(block.GetProperty("caption").GetString()!, "Caption")); break;
                }
            }
            AddSection(main, body, cover);
            main.Document.Save();
            var issues = new OpenXmlValidator().Validate(doc).ToList();
            if (issues.Count > 0) throw new InvalidOperationException(string.Join("\n",issues.Select(x=>x.Description+" "+x.Path?.XPath)));
            Console.WriteLine("VALID " + Path.GetFileName(filename));
        }
    }
    static RunFonts Fonts(bool heading=false) => new() { Ascii="Times New Roman", HighAnsi="Times New Roman", EastAsia=heading?"黑体":"宋体", ComplexScript="Times New Roman" };
    static Run TextRun(string text, int? size=null, bool bold=false)
    {
        var props=new RunProperties();
        if(bold) props.Append(new Bold());
        props.Append(new Color{Val="000000"});
        if(size.HasValue) props.Append(new FontSize{Val=size.Value.ToString()});
        return new Run(props,new Text(text){Space=SpaceProcessingModeValues.Preserve});
    }
    static Paragraph Paragraph(string text,string style) => new(new ParagraphProperties(new ParagraphStyleId{Val=style}),TextRun(text));
    static void Page(Body body) => body.Append(new Paragraph(new Run(new Break{Type=BreakValues.Page})));
    static void AddStyles(MainDocumentPart main, bool compact = false)
    {
        var styles = new Styles(new DocDefaults(
            new RunPropertiesDefault(new RunPropertiesBaseStyle(Fonts(),new Color{Val="000000"},new FontSize{Val="24"})),
            new ParagraphPropertiesDefault(new ParagraphPropertiesBaseStyle(new SpacingBetweenLines{Line="340",LineRule=LineSpacingRuleValues.Auto,After="100"}))));
        void Add(string id,int size,bool bold=false,bool center=false,int? outline=null,bool indent=false)
        {
            var pp=new StyleParagraphProperties();
            if(outline.HasValue) { pp.Append(new KeepNext()); pp.Append(new KeepLines()); }
            pp.Append(new WidowControl());
            pp.Append(new SpacingBetweenLines{Before=outline.HasValue?"180":"0",After=outline.HasValue?"100":"100",Line=id=="Normal"?"420":"340",LineRule=id=="Normal"?LineSpacingRuleValues.Exact:LineSpacingRuleValues.Auto});
            pp.Append(new Indentation{FirstLineChars=indent?200:0});
            pp.Append(new Justification{Val=center?JustificationValues.Center:JustificationValues.Left});
            if(outline.HasValue) pp.Append(new OutlineLevel{Val=outline.Value});
            var rp=new StyleRunProperties(Fonts(bold)); if(bold) rp.Append(new Bold()); rp.Append(new Color{Val="000000"},new FontSize{Val=size.ToString()});
            var style=new Style{Type=StyleValues.Paragraph,StyleId=id,Default=id=="Normal"?true:null};
            style.Append(new StyleName{Val=id}); if(id!="Normal") style.Append(new BasedOn{Val="Normal"});
            style.Append(new PrimaryStyle(),pp,rp); styles.Append(style);
        }
        Add("Normal",24,indent:true); Add("Title",40,true,true); Add("Subtitle",24,false,true);
        Add("Heading1",32,true,outline:0); Add("Heading2",28,true,outline:1);
        Add("Caption",21,false,true); Add("Small",20); Add("Contents",24); Add("TableText",21);
        Add("Code",20);
        var codeStyle = styles.Elements<Style>().Single(x => x.StyleId == "Code");
        codeStyle.StyleParagraphProperties!.SpacingBetweenLines = new SpacingBetweenLines { Before="0", After="25", Line="260", LineRule=LineSpacingRuleValues.Auto };
        codeStyle.StyleRunProperties!.RunFonts = new RunFonts { Ascii="Menlo", HighAnsi="Menlo", EastAsia="宋体", ComplexScript="Menlo" };
        if (compact)
        {
            var normal = styles.Elements<Style>().Single(x => x.StyleId == "Normal");
            normal.StyleParagraphProperties!.Indentation = new Indentation { FirstLineChars=0 };
            normal.StyleParagraphProperties.SpacingBetweenLines = new SpacingBetweenLines { Before="0", After="100", Line="320", LineRule=LineSpacingRuleValues.Exact };
            normal.StyleRunProperties!.FontSize = new FontSize { Val="22" };
            foreach (var (id, size, height) in new[] { ("Title",36,460), ("Subtitle",22,320), ("Heading1",30,440), ("Heading2",25,360), ("Caption",20,280), ("Small",20,280), ("Code",20,260) })
            {
                var style = styles.Elements<Style>().Single(x => x.StyleId == id);
                style.StyleRunProperties!.FontSize = new FontSize { Val=size.ToString() };
                var spacing = style.StyleParagraphProperties!.SpacingBetweenLines!;
                spacing.Line = height.ToString(); spacing.LineRule = LineSpacingRuleValues.Exact;
            }
        }
        main.AddNewPart<StyleDefinitionsPart>().Styles=styles;
    }
    static Table MakeTable(JsonElement block, bool compact = false)
    {
        var widths=block.GetProperty("widths").EnumerateArray().Select(x=>x.GetInt32()).ToArray();
        var table=new Table(new TableProperties(
            new TableWidth{Width=Width.ToString(),Type=TableWidthUnitValues.Dxa},
            new TableBorders(new TopBorder{Val=BorderValues.Single,Size=6,Color="D9D9D9"},new LeftBorder{Val=BorderValues.Single,Size=6,Color="D9D9D9"},new BottomBorder{Val=BorderValues.Single,Size=6,Color="D9D9D9"},new RightBorder{Val=BorderValues.Single,Size=6,Color="D9D9D9"},new InsideHorizontalBorder{Val=BorderValues.Single,Size=4,Color="D9D9D9"},new InsideVerticalBorder{Val=BorderValues.Single,Size=4,Color="D9D9D9"}),
            new TableLayout{Type=TableLayoutValues.Fixed},
            new TableCellMarginDefault(new TopMargin{Width="90",Type=TableWidthUnitValues.Dxa},new TableCellLeftMargin{Width=100,Type=TableWidthValues.Dxa},new BottomMargin{Width="90",Type=TableWidthUnitValues.Dxa},new TableCellRightMargin{Width=100,Type=TableWidthValues.Dxa})));
        table.Append(new TableGrid(widths.Select(w=>new GridColumn{Width=w.ToString()})));
        void Row(IEnumerable<JsonElement> values,bool header)
        {
            var row=new TableRow(new TableRowProperties(new CantSplit())); if(header) row.GetFirstChild<TableRowProperties>()!.Append(new TableHeader());
            int i=0;
            foreach(var val in values)
            {
                var props=new TableCellProperties(new TableCellWidth{Width=widths[i++].ToString(),Type=TableWidthUnitValues.Dxa});
                if(header) props.Append(new Shading{Fill="EAF0F7",Val=ShadingPatternValues.Clear});
                props.Append(new TableCellVerticalAlignment{Val=TableVerticalAlignmentValues.Center});
                var p=Paragraph(val.GetString()!,"TableText");
                p.ParagraphProperties!.Append(new SpacingBetweenLines{Before="0",After="0",Line=compact?"300":"280",LineRule=compact?LineSpacingRuleValues.Exact:LineSpacingRuleValues.Auto});
                if(header) p.GetFirstChild<Run>()!.RunProperties!.PrependChild(new Bold());
                row.Append(new TableCell(props,p));
            }
            table.Append(row);
        }
        Row(block.GetProperty("headers").EnumerateArray(),true);
        foreach(var row in block.GetProperty("rows").EnumerateArray()) Row(row.EnumerateArray(),false);
        return table;
    }
    static void AddImage(MainDocumentPart main,Body body,string path,string caption)
    {
        byte[] bytes=File.ReadAllBytes(path);
        // All authored figures are PNG; dimensions are stored in the IHDR header.
        int w=System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(16,4));
        int h=System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(20,4));
        var part=main.AddImagePart(ImagePartType.Png); using(var stream=File.OpenRead(path)) part.FeedData(stream);
        long cx=Width*635L,cy=cx*h/w;
        var pic=new PIC.Picture(new PIC.NonVisualPictureProperties(new PIC.NonVisualDrawingProperties{Id=0U,Name=Path.GetFileName(path)},new PIC.NonVisualPictureDrawingProperties()),
            new PIC.BlipFill(new A.Blip{Embed=main.GetIdOfPart(part)},new A.Stretch(new A.FillRectangle())),
            new PIC.ShapeProperties(new A.Transform2D(new A.Offset{X=0,Y=0},new A.Extents{Cx=cx,Cy=cy}),new A.PresetGeometry(new A.AdjustValueList()){Preset=A.ShapeTypeValues.Rectangle}));
        var inline=new DW.Inline(new DW.Extent{Cx=cx,Cy=cy},new DW.DocProperties{Id=imageId++,Name=caption,Description=caption},new DW.NonVisualGraphicFrameDrawingProperties(new A.GraphicFrameLocks{NoChangeAspect=true}),new A.Graphic(new A.GraphicData(pic){Uri="http://schemas.openxmlformats.org/drawingml/2006/picture"}));
        body.Append(new Paragraph(new ParagraphProperties(new KeepNext(),new SpacingBetweenLines{Before="100",After="60",Line="240",LineRule=LineSpacingRuleValues.Auto},new Indentation{FirstLineChars=0},new Justification{Val=JustificationValues.Center}),new Run(new Drawing(inline))));
    }
    static void AddSection(MainDocumentPart main,Body body,bool cover)
    {
        var footer=main.AddNewPart<FooterPart>();
        footer.Footer=new Footer(new Paragraph(new ParagraphProperties(new Justification{Val=JustificationValues.Center}),new SimpleField(new Run(new Text("1"))){Instruction="PAGE"}));
        var header=main.AddNewPart<HeaderPart>(); header.Header=new Header(Paragraph("第14组  应用软件开发课程设计","Small"));
        var section=new SectionProperties(new HeaderReference{Type=HeaderFooterValues.Default,Id=main.GetIdOfPart(header)},new FooterReference{Type=HeaderFooterValues.Default,Id=main.GetIdOfPart(footer)},
            new PageSize{Width=11906,Height=16838},new PageMargin{Top=1440,Right=1440,Bottom=1440,Left=1440,Header=720,Footer=720});
        if(cover) section.Append(new TitlePage());
        body.Append(section);
    }
}
