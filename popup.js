

document.addEventListener('DOMContentLoaded', function () {
     

    let cvss = {

        'AV':'',
        'AC':'',
        'PR':'',
        'UI':'',
        'S':'',
        'C':'',
        'I':'',
        'A':''

    }
    var av,ac,pr,ui,s,c,i,a;

    let vectorString = '';

    const radios = document.querySelectorAll('input[type=radio]');
    for (const radio of radios) {
    radio.onclick = (e) => {
        cvss[e.target.name] = e.target.value;
        calculateCvss(cvss);
    }
    }

    function calculateCvss(cvss){

        // https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator/v31/equations

        let impactLevel = 'low';
        var indice = 0.0;
        let cvssScore = 0.0;
        var av,ac,pr,ui,s,c,i,a;

        if(cvss['AV'] =='N') av = 0.85;
        if(cvss['AV'] =='A') av = 0.62;
        if(cvss['AV'] =='L') av = 0.55;
        if(cvss['AV'] =='P') av = 0.2;
        
        if(cvss['AC'] =='L') ac = 0.77;
        if(cvss['AC'] =='H') ac = 0.44;
        
        if(cvss['PR'] =='N') pr = 0.85;
        if(cvss['PR'] =='L') {
            if(cvss['S']=='U') pr = 0.62;    
            else pr = 0.68;
        }
        if(cvss['PR'] =='H')  {
            if(cvss['S']=='U') pr = 0.27;    
            else pr = 0.5;
        }

        if(cvss['UI'] =='N') ui = 0.85;
        if(cvss['UI'] =='R') ui = 0.62;
        if(cvss['S'] =='U') s = 6.42;
        if(cvss['S'] =='C') s = 7.52;
        
        if(cvss['C'] =='H') c = 0.56;
        if(cvss['C'] =='L') c = 0.22;
        if(cvss['C'] =='N') c = 0;
        if(cvss['I'] =='H') i = 0.56;
        if(cvss['I'] =='L') i = 0.22;
        if(cvss['I'] =='N') i = 0;
        if(cvss['A'] =='H') a = 0.56;
        if(cvss['A'] =='L') a = 0.22;
        if(cvss['A'] =='N') a = 0;

        var exploitability = 8.22 * av * ac * pr * ui;
        var iss = (1 - ((1 - c) * (1 - i) * (1 - a)));
        var impact = 0;
        if (cvss['S'] === 'U') {
            impact =  s * iss;
        } else {
            impact = s * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
        }
        if (iss <= 0) {
            indice = 0;
        } else {
            if (cvss['S'] === 'U') {
                indice = Math.min((exploitability + impact), 10);
            } else {
                indice = Math.min((exploitability + impact) * 1.08, 10);
            }
        }
        indice = Math.ceil(indice * 10) / 10;
        cvssScore = indice;
        if(cvssScore >= 9) impactLevel = 'critical';
            else 
                if(cvssScore >= 7) impactLevel = 'high';
                    else
                        if(cvssScore >= 4) impactLevel = 'medium';
                            else
                                if(cvssScore >= 0) impactLevel = 'low';
        vectorString = `CVSS:3.1/AV:${cvss['AV']}/AC:${cvss['AC']}/PR:${cvss['PR']}/UI:${cvss['UI']}/S:${cvss['S']}/C:${cvss['C']}/I:${cvss['I']}/A:${cvss['A']}`;

        

        if (isNaN(cvssScore)) {
            cvssScore = 0.0;
            impactLevel = 'low';
          }

        var vs = document.getElementById('vectorString').innerHTML = vectorString;
        var score = document.querySelector('#score'); ;

        score.innerHTML = cvssScore;
        score.className = impactLevel;
         

    };


    
});
