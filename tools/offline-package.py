"""Offline VSIX builder used when tfx-cli is unavailable. Validate with official tfx in CI."""
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr
import json,zipfile
root=Path(__file__).resolve().parent.parent
m=json.loads((root/'vss-extension.json').read_text())
ct=b'''<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension=".png" ContentType="image/png"/>
  <Default Extension=".js" ContentType="application/javascript"/>
  <Default Extension=".json" ContentType="application/json"/>
  <Default Extension=".md" ContentType="text/markdown"/>
  <Default Extension=".vsixmanifest" ContentType="text/xml"/>
  <Default Extension=".vsomanifest" ContentType="application/json"/>
  <Override ContentType="text/plain" PartName="/LICENSE"/>
</Types>
'''
xml=f'''<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id={quoteattr(m['id'])} Version={quoteattr(m['version'])} Publisher={quoteattr(m['publisher'])}/>
    <DisplayName>{escape(m['name'])}</DisplayName>
    <Description xml:space="preserve">{escape(m['description'])}</Description>
    <GalleryFlags/>
    <Categories>Azure Pipelines</Categories>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Services.Links.GitHub" Value={quoteattr(m['repository']['uri'])}/>
      <Property Id="Microsoft.VisualStudio.Services.Links.Support" Value={quoteattr(m['links']['support']['uri'])}/>
      <Property Id="Microsoft.VisualStudio.Services.Links.Repository" Value={quoteattr(m['links']['repository']['uri'])}/>
      <Property Id="Microsoft.VisualStudio.Services.Branding.Color" Value="#17324d"/>
      <Property Id="Microsoft.VisualStudio.Services.Branding.Theme" Value="dark"/>
    </Properties>
    <Tags>{escape(','.join(m['tags']))}</Tags>
    <Icon>images/extension-icon.png</Icon>
    <License>LICENSE</License>
  </Metadata>
  <Dependencies/>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Services"/>
  </Installation>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Services.Icons.Default" d:Source="File" Path="images/extension-icon.png" Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" d:Source="File" Path="overview.md" Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Content.License" d:Source="File" Path="LICENSE" Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Manifest" d:Source="File" Path="extension.vsomanifest" Addressable="true"/>
  </Assets>
</PackageManifest>
'''
vso=json.dumps({'manifestVersion':1,'repository':m['repository'],'contributions':m['contributions'],'scopes':[],'contributionTypes':[]},indent=4)
dest=root/'dist'/f"{m['publisher']}.{m['id']}-{m['version']}.vsix"
dest.parent.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(dest,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=8)as z:
 z.writestr('[Content_Types].xml',ct)
 z.writestr('extension.vsomanifest',vso)
 z.writestr('extension.vsixmanifest',xml)
 for item in ['images/extension-icon.png','overview.md','LICENSE']:
  z.write(root/item,item)
 for task in ['GrypeInstaller','GrypeScan']:
  for f in (root/task).rglob('*'):
   if f.is_file():z.write(f,f.relative_to(root).as_posix())
print(dest, dest.stat().st_size)
