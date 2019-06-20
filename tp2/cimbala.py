import numpy as np
import scipy.stats as stats

def detectOutliers(jumps):
    outliers, cimbala_data, punto_de_corte = cimbala(jumps.copy())

    print("jumps (rtt diffs): " + str(jumps))
    print("outliers by jumps: " + str(outliers))
    print("cimbala_data: " + str(cimbala_data))
    print("punto_de_corte: " + str(punto_de_corte))

    return outliers

def cimbala(rttDifs):
    outliers = []

    cimbala_data = []
    mean_or = np.mean(rttDifs)
    standardDeviation_or = np.std(rttDifs)
    punto_de_corte = mean_or + standardDeviation_or
    for rttDif in rttDifs:
        cimbala_data.append((np.absolute(rttDif - mean_or)) / standardDeviation_or)

    if len(rttDifs) > 0:
        keepLooking = True
        while keepLooking:
            keepLooking = False
            mean = np.mean(rttDifs)
            standardDeviation = np.std(rttDifs)
            tg = thompsonGamma(rttDifs)
            outlier = None
            for rttDif in rttDifs:
                delta = np.absolute(rttDif - mean)
                #print("delta: " + str(delta) + " t*S: " + str(tg * standardDeviation))
                if (delta > tg * standardDeviation):
                    outlier = rttDif
                    break
            if outlier:
                rttDifs.remove(outlier)
                outliers.append(outlier)
                keepLooking = True

    return outliers, cimbala_data, punto_de_corte


def thompsonGamma(rtts):
    n = len(rtts)
    t_a_2 = stats.t.ppf(1 - 0.025, n - 2)
    sqRootN = np.sqrt(n)
    numerator = t_a_2 * (n - 1)
    denominator = sqRootN * np.sqrt(n - 2 + np.power(t_a_2, 2))
    return numerator / denominator
