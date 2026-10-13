from pathlib import Path
import json,gzip,base64,re
ROOT=Path(__file__).resolve().parents[1]
def build(release):
 vendor=ROOT/'tools/vendor/node_modules';template=(ROOT/'installer/template.html').read_text()
 images={}
 manifest=json.loads((release/'manifest.json').read_text())
 for layout,m in manifest['boards'].items():
  data=(release/m['factory']).read_bytes();images[layout]={**{k:m[k] for k in ['sha256','bytes','flash_size','flash_frequency']},'gzip':base64.b64encode(gzip.compress(data,compresslevel=9,mtime=0)).decode()}
 sdk=(vendor/'esptool-js/bundle.js').read_text();exports=re.search(r'export\{([^}]+)\};?\s*$',sdk)
 if not exports:raise ValueError('Unexpected esptool-js bundle format')
 names={alias.strip():name.strip() for item in exports[1].split(',') for name,alias in [item.split(' as ') if ' as ' in item else (item,item)]}
 sdk=sdk[:exports.start()]+'\nwindow.PDNS_ESP={ESPLoader:'+names['ESPLoader']+',Transport:'+names['Transport']+'};'
 replacements={'/*IMAGE_DATA*/':'window.PDNS_IMAGES='+json.dumps(images,separators=(',',':'))+';','/*CRYPTO_JS*/':(vendor/'crypto-js/crypto-js.js').read_text(),'/*QR_CODE*/':(vendor/'qrcode-generator/qrcode.js').read_text(),'/*ESP_TOOL*/':sdk,'/*INSTALLER*/':(ROOT/'installer/installer.js').read_text()}
 for marker,text in replacements.items():template=template.replace(marker,text.replace('</script','<\\/script'))
 out=release/'Pocket_DNS_USB_Installer.html';out.write_text(template);return out
if __name__=='__main__':build(ROOT/'release')
