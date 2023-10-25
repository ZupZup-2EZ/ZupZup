import { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import * as utils from 'utils';

import {
  TopNavigation,
  RegistInfoInput,
  RegistInfoTitle,
  RegistInfoFrame,
} from 'components';

const RegistInfo = () => {
  const navigate = useNavigate();
  const inputRefForHeight = useRef<HTMLInputElement>(null);
  const inputRefForWeight = useRef<HTMLInputElement>(null);
  const [isNextButtonDisabled, setNextButtonDisabled] = useState<boolean>(true);

  const inputCheck = (
    heightInput: string | undefined,
    weightInput: string | undefined,
  ) => {
    if (heightInput && Number(heightInput) > 100 && Number(heightInput) < 200) {
      if (
        weightInput &&
        Number(weightInput) > 10 &&
        Number(weightInput) < 200
      ) {
        return true;
      }
    }
    return false;
  };

  const handleInputChange = () => {
    const heightInput = inputRefForHeight.current?.value;
    const weightInput = inputRefForWeight.current?.value;
    setNextButtonDisabled(!inputCheck(heightInput, weightInput));
  };

  const handleNextPage = () => {
    if (
      inputCheck(
        inputRefForHeight.current?.value,
        inputRefForWeight.current?.value,
      )
    ) {
      navigate(utils.URL.LOGIN.REGIST_INFO + '/profile', {
        state: {
          height: inputRefForHeight.current?.value,
          weight: inputRefForWeight.current?.value,
        },
      });
    }
  };
  return (
    <RegistInfoFrame.Wrap>
      <TopNavigation />
      <RegistInfoTitle
        mainTitle={'키와 몸무게를 입력해주세요'}
        subTitle={'칼로리 계산에 사용됩니다'}
      />
      <RegistInfoFrame.InputSection>
        <RegistInfoInput
          holderText="예) 170"
          inputRef={inputRefForHeight}
          onChange={handleInputChange}
          title="키 (cm)"
        />
        <RegistInfoInput
          holderText="예) 70"
          inputRef={inputRefForWeight}
          onChange={handleInputChange}
          title="몸무게 (kg)"
        />
      </RegistInfoFrame.InputSection>
      <RegistInfoFrame.NextButton
        disabled={isNextButtonDisabled}
        onClick={handleNextPage}
      >
        다음
      </RegistInfoFrame.NextButton>
    </RegistInfoFrame.Wrap>
  );
};

export default RegistInfo;
