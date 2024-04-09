<p align="center">
	<img src="purpl.png" width=50" />
</p>

# Naïve gRPC purpose limitation and data minimization

This module was implemented to measure the performance improvement of the separation of PAP/PDP and PEP.

The so-called naive approach generates the token based on a policy in the interceptor itself and, consequently, at every 
request. We performed experiments within the same environment as described in our report and used the same measurement 
mechanism. 

The results are as follows:

![Alternativtext](performance_comparison.png)

The results show a significant difference between both approaches while the number of fields does not seem to make a big
difference at the naive approach. Consequently, the token generation itself seem to have a more or less fixed impact. 
However, we have not tested a very large policy with dozens of services and purposes which would probably increase the
latency of the naive approach even further. 

# Citation
To cite the [preprint version of the paper](https://arxiv.org/pdf/2404.05598.pdf) to appear in the Proceedings of the 24th International Conference on Web Engineering (ICWE 2024), use the following BibTeX entry:
```
@InProceedings{loechel2024hookin,
      author={Louis Loechel and Siar-Remzi Akbayin and Elias Grünewald and Jannis Kiesel and Inga Strelnikova and Thomas Janke and Frank Pallas},
      editor={Stefanidis, Kostas and Systa, Kari and Matera, Maristella and Heil, Sebastian and Kondylakis, Haridimos and Quintarelli, Elisa},
      title={{Hook-in Privacy Techniques for gRPC-based Microservice Communication}}, 
      year={2024},
      publisher="Springer Nature Switzerland",
      address="Cham",
      note={to appear in the Proceedings of the 24th International Conference on Web Engineering (ICWE 2024)},
      eprint={2404.05598},
      archivePrefix={arXiv},
      primaryClass={cs.CR},
}
```
