document.getElementById("analyzeBtn").addEventListener("click", async function(event) {
  event.preventDefault();
  const na = await uploadFile();
  generateCharts(na.analysis)
  generateTable(na.analysis)
  let rows = await getPreviousActivity(1)
  generatePreviousActivity(rows)
  document.querySelector('.upload-container').classList.add('display')
  document.querySelector('.further-info-div').classList.add('baj')
});

document.getElementById("analyzeBtnagain").addEventListener("click",async function (event){
  event.preventDefault();
  const na = await uploadFiles();
  console.log(na)
  const canvas = document.getElementById("myChart");
  const canvas2 = document.getElementById("piechart");
  // Check if a chart already exists on this canvas
  const existingChart = Chart.getChart(canvas);
  const existingChart2 = Chart.getChart(canvas2)
  if (existingChart) {
    existingChart.destroy(); // Destroy the existing chart
  }
  if(existingChart2){
    existingChart2.destroy()
  }
  generateCharts(na.analysis)
  generateTable(na.analysis)
  let rows = await getPreviousActivity(1)
  generatePreviousActivity(rows)
  document.querySelector('.upload-container').classList.add('display')
  document.querySelector('.further-info-div').classList.add('baj')
})

function generatePreviousActivity(data){
  const div = document.querySelector('.recent-scan-div')
  let html = `<h3>Previous Activity</h3>`;
  if(data.message === 'Empty'){
    html += `<p>Huh? There seems to be no previous activity!</p>`;
  }
  else{
    let id = 1
    let rows = data.output
    html += `<table border="1" cla>
        <tr>
           <th>ID</th>
           <th>Timestamp</th>
           <th>Packets Scanned</th>
           <th>Anomalies</th>
        </tr>`
    rows.forEach((row) =>{
      html += `<tr>
                <td>${id}</td>
                <td>${row.generated_at || 'NONE'}</td>
                <td>${row.total_packets_count || 'NONE'}</td>
                <td>${(row.total_packets_count - row.benign_count) || 0}</td>
                </tr>`   
      id++ 
    })
    html += `</table>`
  }
  div.innerHTML = html;
}

function generateTable(data){

  function check(flag){
    if (flag){
      return `class="anomaly"`;
    }
  }

  let tableHtml = `<table border="1">
        <tr>
           <th>ID</th>
           <th>Destination Port</th>
           <th>Destination IP</th>
           <th>Result</th>
        </tr>`
  let id = 1
  let flag = true
  data.forEach((dataitem) => {
    flag = true
    if(dataitem.prediction === 'BENIGN'){
      flag = false
    }
    tableHtml+=`
                <tr>
                <td>${id}</td>
                <td>${dataitem.destination_ip || 'NONE'}</td>
                <td>${dataitem.destination_port || 'NONE'}</td>
                <td ${check(flag)} >${dataitem.prediction}</td>
                </tr>`   
    id++ 
  });
  tableHtml += `</table>`
  document.querySelector('.table-container').classList.add('shadow');
  document.getElementById('table').innerHTML = tableHtml;
  document.querySelector('.further-info-div').classList.add('on');
}


function generateCharts(data){
  document.querySelector('.upload-container').classList.add('display')
  const ctx = document.getElementById('myChart');
  ctx.classList.add('chart')
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['BENIGN', 'ANOMALOUS'],
      datasets: [{
        label: '# of Votes',
        data: [data[0].benign_count,data[0].total_packets-data[0].benign_count],
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: false
        }
      }
    }
  });


  const piechart = document.getElementById('piechart');
  piechart.classList.add('chart')
  new Chart(piechart, {
    type: 'doughnut',
    data: {
      labels: ['BENIGN', 'DDoS', 'Bot', 'PortScan', 'Web Attacks'],
      datasets: [{
        label: '# of Votes',
        data: [data[0].benign_count,data[0].ddos_count,data[0].bot_count,data[0].portscan_count,data[0].webattack_count],
        borderWidth: 1,
        backgroundColor: [
          'rgb(54, 162, 235)',
          'rgb(255, 99, 132)',
          'rgb(255, 205, 86)',
          'rgb(0, 195, 62)',
          'rgb(255, 10, 177)'
        ]
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: false
        }
      }
    }
  });

  const chartss = document.querySelector('.charts');
  chartss.classList.add('on');
}

async function uploadFile() {
    let fileInput = document.getElementById("pcapFile");
    let file = fileInput.files[0];

    if (!file) {
      alert("Please select a file!");
      return;
    }

    if (!file.name.match(/\.(pcap|pcapng|csv)$/i)) {
      alert("Please select a valid PCAP file!");
      return;
    }

    let formData = new FormData();
    formData.append("file", file);

  try {
    let response = await fetch("http://localhost:5000/upload", {
      method: "POST",
      body: formData,
      mode: "cors"
    });
    if (!response.ok) {
      throw new Error(`Server returned ${response.status} ${response.statusText}`);
    }
    let data = await response.json();
    return data;
  } catch (error) {
      console.error("Error:", error);
  } 
}

async function uploadFiles() {
  let fileInput = document.getElementById("pcapFiles");
  let file = fileInput.files[0];

  if (!file) {
    alert("Please select a file!");
    return;
  }

  if (!file.name.match(/\.(pcap|pcapng|csv)$/i)) {
    alert("Please select a valid PCAP file!");
    return;
  }

  let formData = new FormData();
  formData.append("file", file);

try {
  let response = await fetch("http://localhost:5000/upload", {
    method: "POST",
    body: formData,
    mode: "cors"
  });
  if (!response.ok) {
    throw new Error(`Server returned ${response.status} ${response.statusText}`);
  }
  let data = await response.json();
  return data;
} catch (error) {
    console.error("Error:", error);
} 
}

async function getPreviousActivity(userId) {
  let user = JSON.stringify({ user: userId });

  try {
    let response = await fetch("http://localhost:5000/getprevactivity", {
      method: "POST",
      headers: {
        "Content-Type": "application/json" 
      },
      body: user,
      mode: "cors"
    });

    if (!response.ok) {
      throw new Error(`Server returned ${response.status} ${response.statusText}`);
    }

    let data = await response.json();
    return data;
  } catch (error) {
    console.error("Error:", error);
    return null;  // ✅ Return null if there's an error
  }
}



