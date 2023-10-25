import { useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import * as utils from 'utils';
import {
  TopNavigation,
  RegistInfoInput,
  RegistInfoSelectBox,
  RegistInfoTitle,
  RegistInfoFrame,
} from 'components';

const RegistInfo = () => {
  const { state } = useLocation();

  const navigate = useNavigate();
  const inputRefForBirthYear = useRef<HTMLInputElement>(null);
  const [gender, setGender] = useState<string>(utils.GENDER.MALE);
  const [isNextButtonDisabled, setNextButtonDisabled] = useState<boolean>(true);

  const handleSelectChange = (event: React.ChangeEvent<HTMLSelectElement>) => {
    setGender(event.target.value);
  };

  const inputCheck = (birthYearInput: string | undefined) => {
    if (
      state.height &&
      state.weight &&
      birthYearInput &&
      Number(birthYearInput) > 1900 &&
      Number(birthYearInput) < 2024
    ) {
      return true;
    }
    return false;
  };

  const handleInputChange = () => {
    const birthYearInput = inputRefForBirthYear.current?.value;
    setNextButtonDisabled(!inputCheck(birthYearInput));
  };

  const handleNextPage = () => {
    if (inputCheck(inputRefForBirthYear.current?.value)) {
      //내가 보낼 데이터
      const postData = {
        height: state.height,
        weight: state.weight,
        gender,
        birthYear: inputRefForBirthYear.current?.value,
      };
      console.log(postData);
      navigate(utils.URL.RESULT.REGIST);
    }
  };
  return (
    <RegistInfoFrame.Wrap>
      <TopNavigation />
      <RegistInfoTitle
        mainTitle={'나이와 성별을 입력해주세요'}
        subTitle={'칼로리 계산에 사용됩니다'}
      />
      <RegistInfoFrame.InputSection>
        <RegistInfoInput
          holderText="예) 1990"
          inputRef={inputRefForBirthYear}
          onChange={handleInputChange}
          title="출생 연도"
        />
        <RegistInfoSelectBox
          title="성별"
          value={gender}
          onChange={handleSelectChange}
        />
      </RegistInfoFrame.InputSection>
      <RegistInfoFrame.NextButton
        disabled={isNextButtonDisabled}
        onClick={handleNextPage}
      >
        가입 완료하기
      </RegistInfoFrame.NextButton>
    </RegistInfoFrame.Wrap>
  );
};

export default RegistInfo;
