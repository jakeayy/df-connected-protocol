<div align=center>

<img width=100% src=.github/assets/banner.webp />
<br><br>
<table border=1>
  <tr>
    <td>
      <img src=.github/assets/avatar.webp height=100 />
    </td>
  </tr>
</table>

<h3>DF Connected Protocol</h3>
<small>Reverse Engineered to it's core.</small>

<br><hr>

<h1>Preview</h1>

<img src=.github/assets/preview.png height=300>

<br><hr>

<h1>About</h1>

Mostly-finished documentation for <a href="https://gamemakerserver.com/">GameMakerServer</a> protocol and networking used in <a href="https://gamejolt.com/games/dontforget/150752">DF Connected</a>. <sup>(v2.7.15)</sup><br>
Powered by Claude Opus 5.5 <sup>(4.8 for more risky work)</sup> and <a href="https://hex-rays.com/ida-pro">IDA Pro</a>

<br>

<table><thead>
  <tr>
    <th>File</th>
    <th>Description</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td><a href="/PROTOCOL.md">PROTOCOL.md</a></td>
    <td>Networking and Protocol documentation + any additional info that you might want to know</td>
  </tr>
  <tr>
    <td><a href="/FORMATTING.md">FORMATTING.md</a></td>
    <td>Info about formatting in text on chat/dialogue boxes etc. (e.g. color formatting). Includes additional info on namecolor commands and more internal knowledge.</td>
  </tr>
  <tr>
    <td><a href="/dfc.lua">dfc.lua</a></td>
    <td>Wireshark filter that covers most of the packets and converts them into readable data.</td>
  </tr>
</tbody>
</table>

<img height=50 src=.github/assets/miku.gif />

<br><hr>

<h1>WARNING (read)</h1>

Anything posted here is done in <b>educational and research purposes</b> to present and possibly educate reader what each of the function does and how it's done, letting them learn how mechanics can or should be done to create a successful project. Creator of this repo <b>is not</b> and <b>will not be</b> responsible for any malicious intent of potential readers of this repo and the only ones responsible for such should be bad actors themselves that use this repo's information in bad manner.
<br><br>
That being said, **by reading and accessing this repo's files you directly accept you won't use the knowledge you find maliciously to attack any of the mentioned above**.

<br><hr>

<h1>Software Used</h1>

<table><thead>
  <tr>
    <th>Software</th>
    <th>Use</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td><a href="https://claude.com/claude-code">Claude Code</a></td>
    <td>AI helper used in this repo</td>
  </tr>
  <tr>
    <td>
    <b>PREVIOUSLY</b>
    <a href="https://github.com/NationalSecurityAgency/ghidra">Ghidra</a> <sup>(v12.1.4)</sup>
    </td>
    <td>Reverse Engineering Tool formely used for repo. Not used anymore because it was very prone to bugs and didn't match well with previously used REA.</td>
  </tr>
    <tr>
    <td>
    <a href="https://hex-rays.com/ida-pro">IDA Pro</a> <sup>(v9.5)</sup>
    </td>
    <td>Reverse Engineering Tool. Matched with it's official IDA Pro MCP make it a way better solution for reverse engineering work.</td>
  </tr>
  <tr>
    <td><a href="https://www.wireshark.org/">Wireshark</a> <sup>(v4.6.9)</sup></td>
    <td>Used to extract real packets of networking flow and confirming if they align with what we have.</td>
  </tr>
</tbody>
</table>

</div>
