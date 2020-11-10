package org.assignmentTracker.service.lecture.impl;

import org.assignmentTracker.entity.Lecture;
import org.assignmentTracker.repository.lecture.LectureRepository;
import org.assignmentTracker.service.lecture.ILectureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * @author Justin Kokolo
 * student number: 218044194
 * Desc: Lecture service implimatation
 * Date: 04 September 2020
 */

@Service
public class LectureServiceImpl implements ILectureService {


    private static ILectureService service = null;
    @Autowired
    private LectureRepository repository;



    @Override
    public Set<Lecture> getAll() {
        return this.repository.findAll().stream().collect(Collectors.toSet());
    }

    @Override
    public Set<Lecture> getAllNamesThatStartWithK() {
        Set<Lecture> lectures = repository.findAll().stream().collect(Collectors.toSet());
        Set<Lecture> LecturesWithK = new HashSet<>();
        for(Lecture lecture : lectures){

            if ( lecture.getName().trim().toLowerCase().startsWith("K")){
                LecturesWithK.add(lecture);
            }

        }
        return LecturesWithK;
    }

    @Override
    public Lecture create(Lecture lecture) {
        return this.repository.save(lecture);
    }

    @Override
    public Lecture read(Integer id) {
        return this.repository.findById(id).orElseGet(null);}

    @Override
    public Lecture update(Lecture lecture) {
        return this.repository.save(lecture);
    }

    @Override
    public boolean delete(Integer id) {

        this.repository.deleteById(id);
        if(this.repository.existsById(id)) return false;
        else return true;
    }
}