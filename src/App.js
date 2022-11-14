import React, { useState } from "react";
import axios from "axios";
import "./App.css";

export default function App() {
  const [final, setFinal] = useState("");
  let fetchData = async () => {
    window.open("http://localhost:3000/log.txt", "_blank");
  };

  return (
    <div className="outer-cont">
      <div className="head">
        <h1>
          A GUI based application for Generation of Network-Packet Parsing Logs
        </h1>

        <h4 style={{marginTop: '2rem', marginLeft: '1.6rem'}}>
          Run the packet analyzer on your terminal and then click the button to
          access the log report of the parsed packets
        </h4>
        <button onClick={fetchData} style={{marginTop: '2rem',fontSize: '25px'}} className="btn btn-primary center"><div className="gen">Generate Log Report</div></button>
        <div className="final">{final}</div>
      </div>
    </div>
  );
}